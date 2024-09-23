use core::{future::poll_fn, task::Poll};

use alloc::boxed::Box;
use futures::future::select;

use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{
        dhcpv4::{Event, Socket as Dhcpv4Socket},
        tcp::{Socket as TcpSocket, State},
        udp,
        udp::Socket as UdpSocket,
    },
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{DhcpOption, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

use uefi::{
    proto::network::snp::{ReceiveFlags, SimpleNetwork},
    table::boot::ScopedProtocol,
    Status,
};

use pixie_shared::Address;

use super::{
    error::{Error, Result},
    MessageKind,
};
use super::{timer::Timer, UefiOS};

pub const PACKET_SIZE: usize = 1514;

type Snp = &'static ScopedProtocol<'static, SimpleNetwork>;

struct SnpDevice {
    snp: Snp,
    tx_buf: [u8; PACKET_SIZE],
    // Received packets might contain Ethernet-related padding (up to 4 bytes).
    rx_buf: [u8; PACKET_SIZE + 4],
}

impl SnpDevice {
    fn new(snp: Snp) -> SnpDevice {
        // Shut down the SNP protocol if needed.
        let _ = snp.shutdown();
        let _ = snp.stop();
        // Initialize.
        snp.start().unwrap();
        snp.initialize(0, 0).unwrap();
        // Enable packet reception.
        snp.receive_filters(
            ReceiveFlags::UNICAST | ReceiveFlags::BROADCAST,
            ReceiveFlags::empty(),
            true,
            None,
        )
        .unwrap();

        SnpDevice {
            snp,
            tx_buf: [0; PACKET_SIZE],
            rx_buf: [0; PACKET_SIZE + 4],
        }
    }
}

impl Drop for SnpDevice {
    fn drop(&mut self) {
        self.snp.stop().unwrap()
    }
}

struct SnpRxToken<'a> {
    packet: &'a mut [u8],
}

struct SnpTxToken<'a> {
    snp: Snp,
    buf: &'a mut [u8],
}

impl<'a> TxToken for SnpTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(len <= self.buf.len());
        let payload = &mut self.buf[..len];
        let ret = f(payload);
        let snp = self.snp;
        snp.transmit(0, payload, None, None, None)
            .expect("Failed to transmit frame");
        // Wait until sending is complete.
        while snp.get_recycled_transmit_buffer_status().unwrap().is_none() {}
        ret
    }
}

impl<'a> RxToken for SnpRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.packet)
    }
}

impl Device for SnpDevice {
    type TxToken<'d> = SnpTxToken<'d>;
    type RxToken<'d> = SnpRxToken<'d>;

    fn receive(&mut self, _: Instant) -> Option<(SnpRxToken<'_>, SnpTxToken<'_>)> {
        let rec = self.snp.receive(&mut self.rx_buf, None, None, None, None);
        if rec == Err(Status::NOT_READY.into()) {
            return None;
        }
        Some((
            SnpRxToken {
                packet: &mut self.rx_buf[..rec.unwrap()],
            },
            SnpTxToken {
                snp: self.snp,
                buf: &mut self.tx_buf,
            },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<SnpTxToken<'_>> {
        Some(SnpTxToken {
            snp: self.snp,
            buf: &mut self.tx_buf,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        let mode = self.snp.mode();
        assert!(mode.media_header_size == 14);
        caps.max_transmission_unit =
            PACKET_SIZE.min((mode.max_packet_size + mode.media_header_size) as usize);
        caps.max_burst_size = Some(1);
        caps
    }
}

pub struct NetworkInterface {
    interface: Interface,
    device: SnpDevice,
    socket_set: SocketSet<'static>,
    dhcp_socket_handle: SocketHandle,
    ephemeral_port_counter: u64,
    pub(super) rx: u64,
    pub(super) tx: u64,
    pub(super) vrx: u64,
    pub(super) vtx: u64,
}

impl NetworkInterface {
    pub fn new(os: UefiOS) -> NetworkInterface {
        let all_handles = os
            .all_handles::<SimpleNetwork>()
            .expect("error getting SimpleNetwork handles");
        let mut device = all_handles
            .iter()
            .filter_map(|x| os.open_handle::<SimpleNetwork>(*x).ok());
        let mut device = SnpDevice::new(Box::leak(Box::new(
            device.next().expect("no network found"),
        )));

        let hw_addr = HardwareAddress::Ethernet(smoltcp::wire::EthernetAddress::from_bytes(
            &device.snp.mode().current_address.0[..6],
        ));

        let mut interface_config = Config::new();
        interface_config.random_seed = os.rng().rand_u64();
        interface_config.hardware_addr = Some(hw_addr);
        let interface = Interface::new(interface_config, &mut device);
        let mut dhcp_socket = Dhcpv4Socket::new();
        dhcp_socket.set_outgoing_options(&[DhcpOption {
            kind: 60,
            data: b"pixie",
        }]);
        let mut socket_set = SocketSet::new(vec![]);
        let dhcp_socket_handle = socket_set.add(dhcp_socket);

        NetworkInterface {
            interface,
            dhcp_socket_handle,
            device,
            socket_set,
            ephemeral_port_counter: os.rng().rand_u64(),
            rx: 0,
            tx: 0,
            vrx: 0,
            vtx: 0,
        }
    }

    fn get_ephemeral_port(&mut self) -> u16 {
        let ans = self.ephemeral_port_counter;
        self.ephemeral_port_counter += 1;
        ((ans % (60999 - 49152)) + 49152) as u16
    }

    pub fn has_ip(&self) -> bool {
        self.ip().is_some()
    }

    pub fn ip(&self) -> Option<Ipv4Address> {
        self.interface.ipv4_addr()
    }

    pub(super) fn poll(&mut self, timer: &Timer) -> bool {
        let now = timer.instant();
        let status = self
            .interface
            .poll(now, &mut self.device, &mut self.socket_set);
        if !status {
            return false;
        }

        let dhcp_status = self
            .socket_set
            .get_mut::<Dhcpv4Socket>(self.dhcp_socket_handle)
            .poll();

        if let Some(dhcp_status) = dhcp_status {
            if let Event::Configured(config) = dhcp_status {
                self.interface.update_ip_addrs(|a| {
                    a.push(IpCidr::Ipv4(config.address)).unwrap();
                });
                if let Some(router) = config.router {
                    self.interface
                        .routes_mut()
                        .add_default_ipv4_route(router)
                        .unwrap();
                }
            } else {
                self.interface.update_ip_addrs(|a| {
                    a.clear();
                });
                self.interface.routes_mut().remove_default_ipv4_route();
            }
        }

        true
    }
}

pub struct TcpStream {
    handle: SocketHandle,
    os: UefiOS,
}

// TODO(veluca): we may leak a fair bit of sockets here. It doesn't really matter, as we won't
// create that many, but still it would be nice to fix eventually.
// Also, trying to use a closed connection may result in panics.
impl TcpStream {
    pub async fn new(os: UefiOS, ip: [u8; 4], port: u16) -> Result<TcpStream> {
        os.wait_for_ip().await;
        const TCP_BUF_SIZE: usize = 1 << 22;
        let mut tcp_socket = TcpSocket::new(
            RingBuffer::new(vec![0; TCP_BUF_SIZE]),
            RingBuffer::new(vec![0; TCP_BUF_SIZE]),
        );
        tcp_socket.set_timeout(Some(Duration::from_secs(5)));
        tcp_socket.set_keep_alive(Some(Duration::from_secs(1)));
        let sport = os.net().get_ephemeral_port();
        tcp_socket.connect(
            os.net().interface.context(),
            IpEndpoint {
                addr: IpAddress::Ipv4(Ipv4Address(ip)),
                port,
            },
            sport,
        )?;

        let handle = os.net().socket_set.add(tcp_socket);

        let ret = TcpStream { handle, os };

        ret.wait_for_state(|state| match state {
            State::Established => Some(Ok(())),
            State::Closed => Some(Err(Error::msg("connection refused"))),
            _ => None,
        })
        .await?;

        Ok(ret)
    }

    pub async fn wait_for_state<T>(&self, f: impl Fn(State) -> Option<T>) -> T {
        poll_fn(move |cx| {
            let state = self
                .os
                .net()
                .socket_set
                .get_mut::<TcpSocket>(self.handle)
                .state();
            let res = f(state);
            if let Some(res) = res {
                Poll::Ready(res)
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }

    pub async fn wait_until_closed(&self) {
        self.wait_for_state(|s| if s == State::Closed { Some(()) } else { None })
            .await;
        self.os.net().socket_set.remove(self.handle);
    }

    async fn fail_if_closed(&self) -> Result<()> {
        self.wait_until_closed().await;
        Err(Error::msg("connection closed"))
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut pos = 0;
        let send = poll_fn(move |cx| {
            let mut net = self.os.net();
            let socket = net.socket_set.get_mut::<TcpSocket>(self.handle);
            let sent = socket.send_slice(&data[pos..]);
            if let Err(err) = sent {
                return Poll::Ready(Err(Error::TcpSend(err)));
            }
            pos += sent.unwrap();
            if pos < data.len() {
                socket.register_send_waker(cx.waker());
                net.tx += sent.unwrap() as u64;
                Poll::Pending
            } else {
                net.tx += sent.unwrap() as u64;
                Poll::Ready(Ok(()))
            }
        });

        select(send, Box::pin(self.fail_if_closed()))
            .await
            .factor_first()
            .0
    }

    /// Returns the number of bytes received (0 if connection is closed on the other end without
    /// receiving any data.
    pub async fn recv(&self, data: &mut [u8]) -> Result<usize> {
        poll_fn(move |cx| {
            let mut net = self.os.net();
            let socket = net.socket_set.get_mut::<TcpSocket>(self.handle);
            if !socket.may_recv() {
                return Poll::Ready(Ok(0));
            }
            let recvd = socket.recv_slice(data);
            if recvd == Err(smoltcp::socket::tcp::RecvError::Finished) {
                return Poll::Ready(Ok(0));
            }
            if let Err(err) = recvd {
                return Poll::Ready(Err(Error::Recv(err)));
            }
            if recvd.unwrap() == 0 {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            } else {
                net.rx += recvd.unwrap() as u64;
                Poll::Ready(Ok(recvd.unwrap()))
            }
        })
        .await
    }

    pub async fn recv_exact(&self, data: &mut [u8]) -> Result<()> {
        let mut pos = 0;
        while pos < data.len() {
            let recvd = self.recv(&mut data[pos..]).await?;
            if recvd == 0 {
                return Err(Error::msg("connection closed"));
            }
            pos += recvd;
        }
        Ok(())
    }

    pub async fn send_u64_le(&self, data: u64) -> Result<()> {
        self.send(&data.to_le_bytes()).await
    }

    pub async fn recv_u64_le(&self) -> Result<u64> {
        let mut buf = [0; 8];
        self.recv_exact(&mut buf).await?;
        Ok(u64::from_le_bytes(buf))
    }

    pub async fn close_send(&self) {
        {
            self.os
                .net()
                .socket_set
                .get_mut::<TcpSocket>(self.handle)
                .close();
        }
        self.wait_for_state(|state| match state {
            State::Closed | State::Closing | State::FinWait1 | State::FinWait2 => Some(()),
            _ => None,
        })
        .await
    }

    pub async fn force_close(&self) {
        {
            self.os
                .net()
                .socket_set
                .get_mut::<TcpSocket>(self.handle)
                .abort();
        }
        self.wait_until_closed().await;
    }
}

pub struct UdpHandle {
    handle: SocketHandle,
    os: UefiOS,
}

impl UdpHandle {
    pub async fn new(os: UefiOS, listen_port: Option<u16>) -> Result<UdpHandle> {
        os.wait_for_ip().await;
        const UDP_BUF_SIZE: usize = 1 << 22;
        const UDP_PACKET_BUF_SIZE: usize = 1 << 10;
        let rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_BUF_SIZE],
            vec![0; UDP_BUF_SIZE],
        );
        let tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_PACKET_BUF_SIZE],
            vec![0; UDP_BUF_SIZE],
        );

        let mut udp_socket = UdpSocket::new(rx_buffer, tx_buffer);
        let sport = if let Some(p) = listen_port {
            p
        } else {
            os.net().get_ephemeral_port()
        };
        udp_socket.bind(sport)?;

        let handle = os.net().socket_set.add(udp_socket);

        let ret = UdpHandle { handle, os };
        Ok(ret)
    }

    pub async fn send(&self, ip: [u8; 4], port: u16, data: &[u8]) -> Result<()> {
        let endpoint = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Address(ip)),
            port,
        };

        Ok(poll_fn(move |cx| {
            let mut net = self.os.net();
            let socket = net.socket_set.get_mut::<UdpSocket>(self.handle);
            if !socket.can_send() {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            } else {
                let status = socket.send_slice(data, endpoint);
                net.tx = net.tx.wrapping_add(data.len() as u64);
                Poll::Ready(status)
            }
        })
        .await?)
    }

    pub async fn recv<'a>(&self, buf: &'a mut [u8; PACKET_SIZE]) -> (&'a mut [u8], Address) {
        let buf2 = &mut *buf;
        let (len, addr) = poll_fn(move |cx| {
            let mut net = self.os.net();
            let socket = net.socket_set.get_mut::<UdpSocket>(self.handle);
            if !socket.can_recv() {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            } else {
                // Cannot fail if can_recv() returned true.
                let recvd = socket.recv_slice(buf2).unwrap();
                let ip = (recvd.1).addr.as_bytes().try_into().unwrap();
                let port = (recvd.1).port;
                Poll::Ready((recvd.0, Address { ip, port }))
            }
        })
        .await;

        self.os.net().rx += len as u64;

        (&mut buf[..len], addr)
    }

    pub fn close(&mut self) {
        self.os
            .net()
            .socket_set
            .get_mut::<UdpSocket>(self.handle)
            .close();
        self.os.net().socket_set.remove(self.handle);
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        self.close()
    }
}
