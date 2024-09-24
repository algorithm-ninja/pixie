use std::{
    net::{IpAddr, Ipv4Addr},
    time::SystemTime,
};

use anyhow::{bail, Result};
use pixie_shared::PACKET_LEN;
use tokio::net::UdpSocket;

use crate::{find_mac, state::State};

pub async fn main(state: &State) -> Result<()> {
    // TODO: do we like port 4043?
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 4043)).await?;
    log::info!("Listening on {}", socket.local_addr()?);

    let mut buf = [0; PACKET_LEN];
    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        let IpAddr::V4(peer_ip) = peer_addr.ip() else {
            bail!("IPv6 is not supported")
        };
        let Ok(peer_mac) = find_mac(peer_ip) else {
            continue;
        };

        state.units.send_if_modified(|units| {
            let Some(unit) = units.iter_mut().find(|unit| unit.mac == peer_mac) else {
                log::warn!("Got ping from unknown unit");
                return false;
            };

            unit.last_ping_timestamp = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            unit.last_ping_msg = buf[..len].to_vec();

            true
        });
    }
}
