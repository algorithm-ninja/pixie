use core::{
    cell::{Ref, RefCell, RefMut},
    ffi::c_void,
    fmt::Write,
    future::{poll_fn, Future, PollFn},
    mem::transmute,
    ptr::NonNull,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};

use alloc::{
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString},
    vec::Vec,
};
use uefi::{
    prelude::{BootServices, RuntimeServices},
    proto::{
        console::text::{Color, Input, Key, Output},
        device_path::{
            build::DevicePathBuilder,
            text::{AllowShortcuts, DevicePathToText, DisplayOnly},
            DevicePath,
        },
        Protocol,
    },
    table::{
        boot::{EventType, ScopedProtocol, TimerTrigger, Tpl},
        runtime::{VariableAttributes, VariableVendor},
        Boot, SystemTable,
    },
    CStr16, Event, Handle, Status,
};

use self::{
    boot_options::BootOptions,
    disk::Disk,
    error::Error,
    executor::Executor,
    net::{NetworkInterface, TcpStream, UdpHandle},
    rng::Rng,
    timer::Timer,
};

mod boot_options;
pub mod disk;
pub mod error;
mod executor;
mod net;
mod rng;
mod timer;

use error::Result;

pub use net::{HttpMethod, PACKET_SIZE};

struct BytesFmt(u64);

impl core::fmt::Display for BytesFmt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 < (1 << 10) {
            write!(f, "{}B", self.0)
        } else if self.0 < (1 << 20) {
            write!(f, "{:.2}KiB", self.0 as f64 / 1024.0)
        } else if self.0 < (1 << 30) {
            write!(f, "{:.2}MiB", self.0 as f64 / (1 << 20) as f64)
        } else {
            write!(f, "{:.2}GiB", self.0 as f64 / (1 << 30) as f64)
        }
    }
}

struct UefiOSImpl {
    boot_services: &'static BootServices,
    runtime_services: &'static RuntimeServices,
    timer: Timer,
    rng: Rng,
    input: Option<ScopedProtocol<'static, Input>>,
    output: Option<ScopedProtocol<'static, Output<'static>>>,
    net: Option<NetworkInterface>,
    messages: VecDeque<(String, MessageKind)>,
}

impl UefiOSImpl {
    pub fn write_with_color(&mut self, msg: &str, fg: Color, bg: Color) {
        let output = self.output.as_mut().unwrap();
        output.set_color(fg, bg).unwrap();
        write!(output, "{}", msg).unwrap();
        output.set_color(Color::White, Color::Black).unwrap();
    }
}

static mut UI_DRAWER: RefCell<Option<Box<dyn Fn(UefiOS) + 'static>>> = RefCell::new(None);
static mut OS: Option<RefCell<UefiOSImpl>> = None;
static OS_CONSTRUCTED: AtomicBool = AtomicBool::new(false);

#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct UefiOS {}

impl !Send for UefiOS {}
impl !Sync for UefiOS {}

unsafe extern "efiapi" fn exit_boot_services(_e: Event, _ctx: Option<NonNull<c_void>>) {
    panic!("You must never exit boot services");
}

impl UefiOS {
    pub fn start<F, Fut>(mut system_table: SystemTable<Boot>, f: F) -> !
    where
        F: FnOnce(UefiOS) -> Fut + 'static,
        Fut: Future<Output = Result<()>>,
    {
        // Never call this function twice.
        assert_eq!(
            OS_CONSTRUCTED.load(core::sync::atomic::Ordering::Relaxed),
            false
        );

        uefi_services::init(&mut system_table).unwrap();

        // Ensure we never exit boot services.
        // SAFETY: the callback panics on exit from boot services, and thus handles exit from boot
        // services correctly by definition.
        unsafe {
            system_table
                .boot_services()
                .create_event(
                    EventType::SIGNAL_EXIT_BOOT_SERVICES,
                    Tpl::NOTIFY,
                    Some(exit_boot_services),
                    None,
                )
                .unwrap();
        }

        // SAFETY: it is now safe to assume that boot and runtime services will be available forever.
        let boot_services = unsafe { transmute(system_table.boot_services()) };
        let runtime_services = unsafe { transmute(system_table.runtime_services()) };

        let timer = Timer::new(boot_services);
        let rng = Rng::new();

        OS_CONSTRUCTED.store(true, core::sync::atomic::Ordering::Relaxed);

        // SAFETY: we guarantee this is the only place we could be modifying OS from, and that
        // nothing can read it until we do so.
        unsafe {
            OS = Some(RefCell::new(UefiOSImpl {
                boot_services,
                runtime_services,
                timer,
                rng,
                input: None,
                output: None,
                net: None,
                messages: VecDeque::new(),
            }))
        }

        let net = NetworkInterface::new(UefiOS {});

        let input = UefiOS {}
            .open_handle(UefiOS {}.all_handles::<Input>().unwrap()[0])
            .unwrap();

        let output = UefiOS {}
            .open_handle(UefiOS {}.all_handles::<Output>().unwrap()[0])
            .unwrap();

        unsafe {
            OS.as_mut().unwrap().borrow_mut().net = Some(net);
            OS.as_mut().unwrap().borrow_mut().input = Some(input);
            OS.as_mut().unwrap().borrow_mut().output = Some(output);
        }

        Executor::init();

        let os = UefiOS {};

        os.spawn(async { f(UefiOS {}).await.unwrap() });

        os.spawn(poll_fn(|cx| {
            let os = UefiOS {}.os().borrow_mut();
            let (mut net, timer) = RefMut::map_split(os, |os| (&mut os.net, &mut os.timer));
            net.as_mut().unwrap().poll(&timer);
            // TODO(veluca): figure out whether we can suspend the task.
            cx.waker().wake_by_ref();
            Poll::Pending
        }));

        os.spawn(async {
            let mut prx = 0;
            let mut ptx = 0;
            loop {
                {
                    let mut net = UefiOS {}.net();
                    net.vrx = net.rx - prx;
                    prx = net.rx;
                    net.vtx = net.tx - ptx;
                    ptx = net.tx;
                }
                UefiOS {}.sleep_us(1_000_000).await;
            }
        });

        os.spawn(async {
            loop {
                UefiOS {}.draw_ui();
                UefiOS {}.sleep_us(1_000_000).await;
            }
        });

        Executor::run()
    }

    fn os(&self) -> &'static RefCell<UefiOSImpl> {
        // SAFETY: OS is only modified during construction of UefiOS; moreover, it is guaranteed
        // not to be None.
        // No concurrent modifications are possible, as `UefiOS` cannot be constructed in another
        // thread.
        unsafe { OS.as_ref().unwrap_unchecked() }
    }

    pub fn timer(&self) -> Ref<'static, Timer> {
        Ref::map(self.os().borrow(), |f| &f.timer)
    }

    pub fn rng(&self) -> RefMut<'static, Rng> {
        RefMut::map(self.os().borrow_mut(), |f| &mut f.rng)
    }

    pub fn net(&self) -> RefMut<'static, NetworkInterface> {
        RefMut::map(self.os().borrow_mut(), |f| f.net.as_mut().unwrap())
    }

    pub fn wait_for_ip(&self) -> PollFn<impl FnMut(&mut Context<'_>) -> Poll<()>> {
        poll_fn(move |cx| {
            let os = UefiOS {};
            if os.net().has_ip() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }

    pub fn sleep_us(&self, us: u64) -> PollFn<impl FnMut(&mut Context<'_>) -> Poll<()>> {
        let tgt = self.timer().micros() as u64 + us;
        poll_fn(move |cx| {
            let os = UefiOS {};
            let now = os.timer().micros() as u64;
            if now >= tgt {
                Poll::Ready(())
            } else {
                // TODO(veluca): actually suspend the task.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }

    /// WARNING: this function halts all tasks
    pub fn strong_sleep_us(&self, us: u64) {
        let bs = self.os().borrow().boot_services;
        // SAFETY: we are not using a callback
        let e = unsafe {
            bs.create_event(EventType::TIMER, Tpl::NOTIFY, None, None)
                .unwrap()
        };
        bs.set_timer(&e, TimerTrigger::Relative(10 * us)).unwrap();
        bs.wait_for_event(&mut [e]).unwrap();
    }

    pub fn get_variable(
        &self,
        name: &str,
        vendor: &VariableVendor,
    ) -> Result<(Vec<u8>, VariableAttributes)> {
        // name.len() should be enough, but...
        let mut name_buf = vec![0u16; name.len() * 2 + 16];
        let name = CStr16::from_str_with_buf(name, &mut name_buf).unwrap();
        let size = self
            .os()
            .borrow_mut()
            .runtime_services
            .get_variable_size(name, vendor)
            .map_err(|e| Error::Generic(format!("Error getting variable: {:?}", e)))?;

        let mut var_buf = vec![0u8; size];
        let (var, attrs) = self
            .os()
            .borrow_mut()
            .runtime_services
            .get_variable(name, vendor, &mut var_buf)
            .map_err(|e| Error::Generic(format!("Error getting variable: {:?}", e)))?;
        Ok((var.to_vec(), attrs))
    }

    pub fn set_variable(
        &self,
        name: &str,
        vendor: &VariableVendor,
        attrs: VariableAttributes,
        data: &[u8],
    ) -> Result<()> {
        // name.len() should be enough, but...
        let mut name_buf = vec![0u16; name.len() * 2 + 16];
        let name = CStr16::from_str_with_buf(name, &mut name_buf).unwrap();
        self.os()
            .borrow_mut()
            .runtime_services
            .set_variable(name, vendor, attrs, data)
            .map_err(|e| Error::Generic(format!("Error setting variable: {:?}", e)))?;
        Ok(())
    }

    pub fn boot_options(&self) -> BootOptions {
        BootOptions { os: *self }
    }

    pub fn device_path_to_string(&self, device: &DevicePath) -> String {
        let os = self.os().borrow();
        let handle = os
            .boot_services
            .get_handle_for_protocol::<DevicePathToText>()
            .unwrap();
        let device_path_to_text = os
            .boot_services
            .open_protocol_exclusive::<DevicePathToText>(handle)
            .unwrap();
        device_path_to_text
            .convert_device_path_to_text(
                os.boot_services,
                device,
                DisplayOnly(true),
                AllowShortcuts(true),
            )
            .unwrap()
            .to_string()
    }

    /// Find the topmost device that implements this protocol.
    fn handle_on_device<P: Protocol>(&self, device: &DevicePath) -> Handle {
        let os = self.os().borrow();
        for i in 0..device.node_iter().count() {
            let mut buf = vec![];
            let mut dev = DevicePathBuilder::with_vec(&mut buf);
            for node in device.node_iter().take(i + 1) {
                dev = dev.push(&node).unwrap();
            }
            let mut dev = dev.finalize().unwrap();
            if let Ok(h) = os.boot_services.locate_device_path::<P>(&mut dev) {
                return h;
            }
        }
        // TODO(veluca): bubble up errors.
        panic!("handle not found");
    }

    fn all_handles<P: Protocol>(&self) -> Result<Vec<Handle>> {
        Ok(self.os().borrow().boot_services.find_handles::<P>()?)
    }

    fn open_handle<P: Protocol>(&self, handle: Handle) -> Result<ScopedProtocol<'static, P>> {
        Ok(self
            .os()
            .borrow()
            .boot_services
            .open_protocol_exclusive::<P>(handle)?)
    }

    fn open_protocol_on_device<P: Protocol>(
        &self,
        device: &DevicePath,
    ) -> Result<ScopedProtocol<'static, P>> {
        self.open_handle::<P>(self.handle_on_device::<P>(device))
    }

    pub fn open_first_disk(&self) -> Disk {
        Disk::new(*self)
    }

    pub async fn connect(&self, ip: (u8, u8, u8, u8), port: u16) -> Result<TcpStream> {
        TcpStream::new(*self, ip, port).await
    }

    pub async fn udp_bind(&self, port: Option<u16>) -> Result<UdpHandle> {
        UdpHandle::new(*self, port).await
    }

    pub async fn http(
        &self,
        ip: (u8, u8, u8, u8),
        port: u16,
        method: HttpMethod<'_>,
        path: &[u8],
    ) -> Result<Vec<u8>> {
        net::http(*self, ip, port, method, path).await
    }

    pub async fn read_key(&self) -> Result<Key> {
        Ok(poll_fn(move |cx| {
            let key = self.os().borrow_mut().input.as_mut().unwrap().read_key();
            if let Err(e) = key {
                return Poll::Ready(Err(e));
            }
            let key = key.unwrap();
            if let Some(key) = key {
                return Poll::Ready(Ok(key));
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await?)
    }

    pub fn write_with_color(&self, msg: &str, fg: Color, bg: Color) {
        self.os().borrow_mut().write_with_color(msg, fg, bg);
    }

    fn draw_ui(&self) {
        // Write the header.
        {
            let time = self.timer().micros() / 1_000_000;
            let ip = self.net().ip();
            let mut os = self.os().borrow_mut();

            let mode = os.output.as_mut().unwrap().current_mode().unwrap().unwrap();
            let (cols, rows) = (mode.columns(), mode.rows());

            os.output.as_mut().unwrap().clear().unwrap();
            os.write_with_color(&format!("uptime: {:10}s", time), Color::White, Color::Black);

            os.output
                .as_mut()
                .unwrap()
                .set_cursor_position(cols / 3, 0)
                .unwrap();
            if let Some(ip) = ip {
                os.write_with_color(&format!("IP: {}", ip), Color::White, Color::Black);
            } else {
                os.write_with_color("DHCP...", Color::Yellow, Color::Black);
            }

            os.output
                .as_mut()
                .unwrap()
                .set_cursor_position(2 * cols / 3, 0)
                .unwrap();
            let vrx = os.net.as_ref().unwrap().vrx;
            let vtx = os.net.as_ref().unwrap().vtx;
            os.write_with_color(
                &format!("rx: {}/s tx: {}/s", BytesFmt(vrx), BytesFmt(vtx)),
                Color::White,
                Color::Black,
            );

            os.output
                .as_mut()
                .unwrap()
                .set_cursor_position(0, 2)
                .unwrap();

            // TODO(veluca): find a better solution.
            let messages: Vec<_> = os.messages.iter().cloned().collect();

            for (line, kind) in messages {
                let fg_color = match kind {
                    MessageKind::Debug => Color::LightGray,
                    MessageKind::Info => Color::White,
                    MessageKind::Warning => Color::Yellow,
                    MessageKind::Error => Color::Red,
                };
                os.write_with_color(&line, fg_color, Color::Black);
                os.write_with_color("\n", Color::Black, Color::Black);
            }
            os.write_with_color("\n", Color::Black, Color::Black);
        }
        // SAFETY: there are no threads, and UI_DRAWER can never be modified (only its contents
        // can, and RefCell protects that).
        let ui_drawer = unsafe { UI_DRAWER.borrow_mut() };
        if let Some(ui) = &*ui_drawer {
            ui(*self);
        }
    }

    pub fn force_ui_redraw(&self) {
        if self.os().borrow().output.is_none() {
            return;
        }
        self.draw_ui()
    }

    pub fn set_ui_drawer<F: Fn(UefiOS) + 'static>(&self, f: F) {
        let f: Option<Box<dyn Fn(UefiOS)>> = Some(Box::new(f));
        // SAFETY: there are no threads, and UI_DRAWER is never modified.
        unsafe {
            UI_DRAWER.replace(f);
        }
    }

    pub fn append_message(&self, msg: String, kind: MessageKind) {
        {
            let mut os = self.os().borrow_mut();
            os.messages.push_back((msg, kind));
            const MAX_MESSAGES: usize = 5;
            if os.messages.len() > MAX_MESSAGES {
                os.messages.pop_front();
            }
        }
        self.force_ui_redraw();
    }

    /// Spawn a new task.
    pub fn spawn<Fut>(&self, f: Fut)
    where
        Fut: Future<Output = ()> + 'static,
    {
        Executor::spawn(f)
    }

    pub fn reset(&self) -> ! {
        self.os().borrow().runtime_services.reset(
            uefi::table::runtime::ResetType::Warm,
            Status::SUCCESS,
            None,
        )
    }
}

#[derive(Clone, Copy)]
pub enum MessageKind {
    Debug,
    Info,
    Warning,
    Error,
}
