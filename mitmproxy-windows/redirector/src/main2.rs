
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::{env, thread};

use anyhow::{anyhow, Context, Result};
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::{debug, error, info, warn};
use lru_time_cache::LruCache;
use mitmproxy::intercept_conf::{InterceptConf, ProcessInfo};
use mitmproxy::ipc;
use mitmproxy::ipc::FromProxy;
use mitmproxy::packet_sources::windows::IPC_BUF_SIZE;
use mitmproxy::windows::network::network_table;
use mitmproxy::processes::get_process_name;
use mitmproxy::MAX_PACKET_SIZE;
use prost::Message;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, PipeMode};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use windivert::address::WinDivertAddress;
use windivert::prelude::*;
use std::sync::{Arc, atomic::{AtomicBool}};
use futures;
use futures::StreamExt;
use flexi_logger::{Logger, FileSpec};
use net_route::RouteChange::{Add, Delete};
use std::sync::atomic::Ordering;
use net_route::Route;
use windivert::CloseAction::Nothing;

#[derive(Debug)]
enum Event {
    NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
    SocketInfo(WinDivertAddress<SocketLayer>),
    Ipc(ipc::from_proxy::Message),
}

#[derive(Debug)]
enum ConnectionState {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    Intercept(ProcessInfo),
}

struct ActiveListeners(HashMap<(SocketAddr, TransportProtocol), ProcessInfo>);

impl ActiveListeners {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
        process_info: ProcessInfo,
    ) -> Option<ProcessInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            // Dual-stack binds: binding to [::] actually binds to 0.0.0.0 as well.
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.insert((socket, protocol), process_info)
    }

    pub fn remove(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<ProcessInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.remove(&(socket, protocol))
    }

    pub fn get(&self, mut socket: SocketAddr, protocol: TransportProtocol) -> Option<&ProcessInfo> {
        if !self.0.contains_key(&(socket, protocol)) {
            socket.set_ip(Ipv4Addr::UNSPECIFIED.into());
        }
        self.0.get(&(socket, protocol))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    Logger::try_with_str("info")?
        .log_to_file(FileSpec::default().basename("windows-redirector").suffix("log")) // Log to a file
        .append() // Append to the log file, don't overwrite
        .start()?;
    
    let args: Vec<String> = env::args().collect();
    let pipe_name = args
        .get(1)
        .map(|x| x.as_str())
        .unwrap_or(r"\\.\pipe\mitmproxy-transparent-proxy");

    let ipc_client = ClientOptions::new()
        .pipe_mode(PipeMode::Message)
        .open(pipe_name)
        .context("Cannot open pipe")?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let (mut ipc_tx, ipc_rx) = mpsc::unbounded_channel::<ipc::PacketWithMeta>();

    // We currently rely on handles being automatically closed when the program exits.
    // only needed for forward mode
    // let _icmp_handle = WinDivert::new("icmp", WinDivertLayer::Network, 1042, WinDivertFlags::new().set_drop()).context("Error opening WinDivert handle")?;

    let inject_handle = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;
    let tx_clone = event_tx.clone();
    tokio::spawn(async move { let _ = windivert_manager(tx_clone).await; });
    let mut state = InterceptConf::disabled();
    event_tx.send(Event::Ipc(ipc::from_proxy::Message::InterceptConf(state.clone().into())))?;

    tokio::spawn(async move {
        if let Err(e) = handle_ipc(ipc_client, ipc_rx, event_tx).await {
            error!("Error handling IPC: {}", e);
            //std::process::exit(1);
        }
    });

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
        Duration::from_secs(60 * 10),
    );
    let mut active_listeners = ActiveListeners::new();

    loop {
        let result = event_rx.recv().await.unwrap();
        match result {
            Event::NetworkPacket(address, data) => {
                // We received a network packet and now need to figure out what to do with it.

                let packet = match InternetPacket::try_from(data) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                debug!(
                    "Received packet: {} {} {}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.payload().len()
                );

                let is_multicast = packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
                let is_loopback_only =
                    packet.src_ip().is_loopback() && packet.dst_ip().is_loopback();
                if is_multicast || is_loopback_only {
                    debug!(
                        "skipping multicast={} loopback={}",
                        is_multicast, is_loopback_only
                    );
                    inject_handle.send(&WinDivertPacket {
                        address,
                        data: packet.inner().into(),
                    })?;
                    continue;
                }

                match connections.get_mut(&packet.connection_id()) {
                    Some(state) => match state {
                        ConnectionState::Known(s) => {
                            process_packet(address, packet, s, &inject_handle, &mut ipc_tx).await?;
                        }
                        ConnectionState::Unknown(packets) => {
                            packets.push((address, packet));
                        }
                    },
                    None => {
                        if address.outbound() {
                            // We expect a corresponding socket event soon.
                            debug!("Adding unknown packet: {}", packet.connection_id());
                            connections.insert(
                                packet.connection_id(),
                                ConnectionState::Unknown(vec![(address, packet)]),
                            );
                        } else {
                            // For incoming packets, there won't be a socket event if we capture
                            // before it reaches the socket, so we need to make a decision now.
                            let action = {
                                if let Some(proc_info) =
                                    active_listeners.get(packet.dst(), packet.protocol())
                                {
                                    debug!(
                                        "Inbound packet for known application: {:?} ({})",
                                        &proc_info.process_name, &proc_info.pid
                                    );
                                    if state.should_intercept(proc_info) {
                                        ConnectionAction::Intercept(proc_info.clone())
                                    } else {
                                        ConnectionAction::None
                                    }
                                } else {
                                    debug!("Unknown inbound packet. Passing through.");
                                    ConnectionAction::None
                                }
                            };
                            insert_into_connections(
                                packet.connection_id(),
                                &action,
                                &address.event(),
                                &mut connections,
                                &inject_handle,
                                &mut ipc_tx,
                            )
                            .await?;
                            process_packet(address, packet, &action, &inject_handle, &mut ipc_tx)
                                .await?;
                        }
                    }
                }
            }
            Event::SocketInfo(address) => {
                if address.process_id() == 4 {
                    // We get some weird operating system events here, which are not useful.
                    debug!("Skipping PID 4");
                    continue;
                }

                let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                    warn!("Unknown transport protocol: {}", address.protocol());
                    continue;
                };
                let connection_id = ConnectionId {
                    proto,
                    src: SocketAddr::from((address.local_address(), address.local_port())),
                    dst: SocketAddr::from((address.remote_address(), address.remote_port())),
                };

                if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
                    continue;
                }

                match address.event() {
                    WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                        let make_entry = match connections.get(&connection_id) {
                            None => true,
                            Some(e) => matches!(e, ConnectionState::Unknown(_)),
                        };

                        debug!(
                            "{:<15?} make_entry={} pid={} {}",
                            address.event(),
                            make_entry,
                            address.process_id(),
                            connection_id
                        );

                        if !make_entry {
                            continue;
                        }

                        let proc_info = {
                            let pid = address.process_id();
                            ProcessInfo {
                                pid,
                                process_name: get_process_name(pid)
                                    .map(|x| x.to_string_lossy().into_owned())
                                    .ok(),
                            }
                        };

                        let action = if state.should_intercept(&proc_info) {
                            ConnectionAction::Intercept(proc_info)
                        } else {
                            ConnectionAction::None
                        };

                        insert_into_connections(
                            connection_id,
                            &action,
                            &address.event(),
                            &mut connections,
                            &inject_handle,
                            &mut ipc_tx,
                        )
                        .await?;
                    }
                    WinDivertEvent::SocketListen => {
                        let pid = address.process_id();
                        let process_name = get_process_name(pid)
                            .map(|x| x.to_string_lossy().into_owned())
                            .ok();
                        debug!("Registering {:?} on {}.", process_name, connection_id.src);
                        active_listeners.insert(
                            connection_id.src,
                            proto,
                            ProcessInfo { pid, process_name },
                        );
                    }
                    WinDivertEvent::SocketClose => {
                        // We cannot clean up here because there are still final packets on connections after this event,
                        // But at least we can release memory for unknown connections.
                        if let Some(ConnectionState::Unknown(packets)) =
                            connections.get_mut(&connection_id)
                        {
                            packets.clear();
                        }

                        // There might be listen sockets we can clean up.
                        active_listeners.remove(connection_id.src, proto);
                    }
                    _ => {}
                }
            }
            Event::Ipc(ipc::from_proxy::Message::Packet(ipc::Packet { data: buf })) => {
                let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
                // if outbound is false, incoming connections are not re-injected into the right iface.
                address.set_outbound(true);
                address.set_ip_checksum(false);
                address.set_tcp_checksum(false);
                address.set_udp_checksum(false);

                let packet = match InternetPacket::try_from(buf) {
                    Ok(p) => p,
                    Err(e) => {
                        info!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                debug!(
                    "Injecting: {} {} with outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    address.outbound(),
                    address.loopback()
                );

                let packet = WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                };

                inject_handle.send(&packet)?;
            }
            Event::Ipc(ipc::from_proxy::Message::InterceptConf(conf)) => {
                state = conf.try_into()?;
                info!("{}", state.description());

                // Handle preexisting connections.
                connections.clear();
                active_listeners.clear();
                for e in network_table()? {
                    let proc_info = ProcessInfo {
                        pid: e.pid,
                        process_name: get_process_name(e.pid)
                            .map(|x| x.to_string_lossy().into_owned())
                            .ok(),
                    };
                    let proto = TransportProtocol::try_from(e.protocol)?;
                    if e.remote_addr.ip().is_unspecified() {
                        active_listeners.insert(e.local_addr, proto, proc_info);
                    } else {
                        let connection_id = ConnectionId {
                            proto,
                            src: e.local_addr,
                            dst: e.remote_addr,
                        };
                        let action = if state.should_intercept(&proc_info) {
                            ConnectionAction::Intercept(proc_info)
                        } else {
                            ConnectionAction::None
                        };
                        insert_into_connections(
                            connection_id,
                            &action,
                            &WinDivertEvent::ReflectOpen,
                            &mut connections,
                            &inject_handle,
                            &mut ipc_tx,
                        )
                        .await?;
                    }
                }
            }
        }
    }
}

async fn handle_ipc(
    mut ipc: NamedPipeClient,
    mut ipc_rx: UnboundedReceiver<ipc::PacketWithMeta>,
    tx: UnboundedSender<Event>,
) -> Result<()> {
    let mut buf = [0u8; IPC_BUF_SIZE];
    loop {
        tokio::select! {
            r = ipc.read(&mut buf) => {
                match r {
                    Ok(len) if len > 0 => {

                        let mut cursor = Cursor::new(&buf[..len]);
                        let Ok(FromProxy { message: Some(message)}) = FromProxy::decode(&mut cursor) else {
                            return Err(anyhow!("Received invalid IPC message: {:?}", &buf[..len]));
                        };
                        assert_eq!(cursor.position(), len as u64);

                        tx.send(Event::Ipc(message))?;
                    }
                    _ => {
                        info!("IPC read failed. Exiting. {:?}",r);
                        std::process::exit(0);
                    }
                }
            },
            Some(packet) = ipc_rx.recv() => {
                packet.encode(&mut buf.as_mut_slice())?;
                let len = packet.encoded_len();

                ipc.write_all(&buf[..len]).await?;
            }
        }
    }
}

fn compare_routes(first: Route, second: Route) -> Route {
    if first.destination == Ipv4Addr::new(0,0,0,0) && second.destination != Ipv4Addr::new(0,0,0,0) {
        return first;
    }
    if first.destination != Ipv4Addr::new(0,0,0,0) && second.destination == Ipv4Addr::new(0,0,0,0) {
        return second;
    }
    if first.destination != Ipv4Addr::new(0,0,0,0) && second.destination != Ipv4Addr::new(0,0,0,0) {
        if first.metric.unwrap_or(9999) < second.metric.unwrap_or(9999) {
            return first;
        }
    }
    // here we have both destinations == "0.0.0.0"
    if first.gateway == Some(IpAddr::V4(Ipv4Addr::new(0,0,0,0))) && second.gateway != Some(IpAddr::V4(Ipv4Addr::new(0,0,0,0))) {
        return first;
    }
    if first.gateway != Some(IpAddr::V4(Ipv4Addr::new(0,0,0,0))) && second.gateway == Some(IpAddr::V4(Ipv4Addr::new(0,0,0,0))) {
        return second;
    }
    // here we have either both gateways equal or different than "0.0.0.0"
    
    if first.metric.unwrap_or(9999) < second.metric.unwrap_or(9999) {
        return first;
    }
    return second;
} 

/// Repeatedly call WinDivertRecvEx to get network packets and feed them into the channel.
async fn windivert_manager(tx: UnboundedSender<Event>) -> Result<()> {
    loop {
        let stop_flag = Arc::new(AtomicBool::new(false));

        let handle = net_route::Handle::new()?;
        let stream = handle.list().await?;
        let mut best_route = Route { destination: "192.168.1.1".parse().unwrap(), // Example required field
                                    prefix: 24, // Example required field
                                    gateway: None,  // Example optional field
                                    ifindex: None,  // Example optional field
                                    metric: None,   // Example optional field
                                    luid: None };
        let mut if_idx = 0;
        info!("Querying route table...");
        for route in stream {
            if best_route.luid == None {
                best_route = route;
                continue;
            }
            
            best_route = compare_routes(best_route, route).clone();
            if_idx = best_route.ifindex.unwrap_or(0);
        }
        info!("Querying route table done.");
        info!("Setting ifIndex for {:?}", best_route);

        let mut windivert_filter = "tcp || udp".to_string();
        if if_idx != 0 {
            windivert_filter = format!("(tcp || udp) && ifIdx == {}",if_idx);
        }

        let socket_handle = WinDivert::socket(
            "tcp || udp",
            1041,
            WinDivertFlags::new().set_recv_only().set_sniff(),
        )?;
        let network_handle = WinDivert::network(&windivert_filter, 1040, WinDivertFlags::new())?;
        
        let tx_clone = tx.clone();
        let stop_flag_clone = Arc::clone(&stop_flag);
        let socket_thread = thread::spawn(move || relay_socket_events(socket_handle, tx_clone, stop_flag_clone));

        let tx_clone = tx.clone();
        let stop_flag_clone = Arc::clone(&stop_flag);
        let network_thread = thread::spawn(move || relay_network_events(network_handle, tx_clone, stop_flag_clone));

        let stream = handle.route_listen_stream();
        futures::pin_mut!(stream);
        info!("Waiting for changes... ");
        while let Some(event) = stream.next().await {
            info!("Matching event...");
            match event {
                Add(_route) | Delete(_route) => {
                    info!("Matched an add/delete event... {:?}",_route);
                    if _route.destination == Ipv4Addr::new(0,0,0,0) {
                        info!("Resetting...");
                        thread::sleep(Duration::from_millis(1000));
                        stop_flag.store(true,Ordering::SeqCst);
                        // We use timeout because of the nature of WinDivert crate. If we listen on a wrong interface, 
                        // the recv function is blocking and we cannot exit otherwise.
                        let _ = socket_thread.join_timeout(Duration::from_secs(1));
                        info!("Socket stopped...");
                        let _ = network_thread.join_timeout(Duration::from_secs(1));
                        info!("Network stopped...");
                        break;
                    }  
                }  
                _ => {
                    info!("Nothing matched...");
                }
            }
        }
    }
}

// Extending thread join with timeout
trait JoinTimeout {
    fn join_timeout(&self, timeout: Duration) -> Result<(), ()>;
}

impl JoinTimeout for thread::JoinHandle<()> {
    fn join_timeout(&self, timeout: Duration) -> Result<(), ()> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if thread::panicking() {
                return Err(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(())
        
    }
}

/// Repeatedly call WinDivertRecvEx to get socket info and feed them into the channel.
fn relay_socket_events(mut handle: WinDivert<SocketLayer>, tx: UnboundedSender<Event>, stop_flag: Arc<AtomicBool>) {
    loop {
        let packets = handle.recv_ex(1); // FIXME: more?
        if stop_flag.load(Ordering::SeqCst) == true {
            let _ = handle.close(Nothing);
            info!("Thread socket stopping...");
            return;
        }
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::SocketInfo(packet.address)).is_err() {
                        return; // main thread shut down.
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

/// Repeatedly call WinDivertRecvEx to get network packets and feed them into the channel.
fn relay_network_events(mut handle: WinDivert<NetworkLayer>, tx: UnboundedSender<Event>, stop_flag: Arc<AtomicBool>) {
    const MAX_PACKETS: usize = 1;
    let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
    loop {
        let packets = handle.recv_ex(Some(&mut buf), MAX_PACKETS);
        if stop_flag.load(Ordering::SeqCst) == true {
            info!("Thread network stopping...");
            let _ = handle.close(Nothing);
            return;
        }
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx
                        .send(Event::NetworkPacket(packet.address, packet.data.into()))
                        .is_err()
                    {
                        return; // main thread shut down.
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

async fn insert_into_connections(
    connection_id: ConnectionId,
    action: &ConnectionAction,
    event: &WinDivertEvent,
    connections: &mut LruCache<ConnectionId, ConnectionState>,
    inject_handle: &WinDivert<NetworkLayer>,
    ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
) -> Result<()> {
    debug!("Adding: {} with {:?} ({:?})", &connection_id, action, event);
    // no matter which action we do, the reverse direction is whitelisted.

    let existing1 = connections.insert(
        connection_id.reverse(),
        ConnectionState::Known(ConnectionAction::None),
    );
    let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing1 {
        for (a, p) in packets {
            process_packet(a, p, &ConnectionAction::None, inject_handle, ipc_tx).await?;
        }
    }
    if let Some(ConnectionState::Unknown(packets)) = existing2 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, ipc_tx).await?;
        }
    }
    Ok(())
}

async fn process_packet(
    address: WinDivertAddress<NetworkLayer>,
    mut packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &WinDivert<NetworkLayer>,
    ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
) -> Result<()> {
    match action {
        ConnectionAction::None => {
            debug!(
                "Forwarding: {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                address.outbound(),
                address.loopback()
            );
            inject_handle
                .send(&WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
            debug!(
                "Intercepting: {} {} outbound={} loopback={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                address.outbound(),
                address.loopback()
            );

            if !address.ip_checksum() {
                packet.recalculate_ip_checksum();
            }
            if !address.tcp_checksum() {
                packet.recalculate_tcp_checksum();
            }
            if !address.udp_checksum() {
                packet.recalculate_udp_checksum();
            }

            ipc_tx.send(ipc::PacketWithMeta {
                data: packet.inner(),
                tunnel_info: Some(ipc::TunnelInfo {
                    pid: *pid,
                    process_name: process_name.clone(),
                }),
            })?;
        }
    }
    Ok(())
}
