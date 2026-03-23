//! Module responsible for registering hooks targeting socket operation syscalls.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_arguments)]

pub(crate) mod hostname;
pub(crate) mod ops;
pub(crate) mod utils;

use std::{
    net::SocketAddr,
    ops::Not,
    sync::Arc,
};

use mirrord_intproxy_protocol::{
    ConnMetadataRequest, ConnMetadataResponse, OutgoingConnMetadataRequest, PortSubscribe,
};
use mirrord_layer_lib::{
    detour::Detour,
    error::{ConnectError, HookError, HookResult, LayerResult, SendToError, windows::WindowsError},
    proxy_connection::make_proxy_request_with_response,
    setup::{LayerSetup, NetworkHookConfig, setup},
    socket::{
        Bound, Connected, SOCKETS, SocketAddrExt, SocketState, UserSocket,
        dns::{
            remote_dns_resolve_via_proxy,
            windows::{
                MANAGED_ADDRINFO, free_managed_addrinfo, getaddrinfo, utils::ManagedAddrInfoAny,
            },
        },
        get_connected_addresses,
        hostname::remote_hostname_string,
        is_socket_managed,
        ops::{ConnectResult, get_last_error, send_to, socket},
        sockets::{SocketDescriptor, socket_kind_from_type},
    },
};
use mirrord_layer_macro::hook_guard_fn;
use socket2::SockAddr;
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{BOOL, FALSE, INT, TRUE},
        winerror::{ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA},
        ws2def::{ADDRINFOA, ADDRINFOW, LPWSABUF, SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR},
    },
    um::{
        minwinbase::OVERLAPPED,
        sysinfoapi::*,
        winsock2::{
            HOSTENT, INVALID_SOCKET, IPPORT_RESERVED, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET,
            SOCKET_ERROR, WSA_IO_PENDING, WSAEACCES, WSAECONNABORTED, WSAECONNREFUSED, WSAEFAULT,
            WSAGetLastError, WSAOVERLAPPED, WSASend, WSASetLastError,
        },
    },
};
use windows_strings::{PCSTR, PCWSTR};

use self::{
    hostname::{handle_hostname_ansi, handle_hostname_unicode, is_remote_hostname},
    ops::{WSABufferData, get_connectex_original, hook_connectex_extension, log_connection_result},
    utils::{
        AutoCloseSocket, ERROR_SUCCESS_I32, create_thread_local_hostent, determine_local_address,
        get_actual_bound_address,
    },
};
use crate::{DetourEngineGuard, apply_hook, process::elevation::require_elevation};

/// Windows socket hook for socket creation
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn socket_detour(af: INT, type_: INT, protocol: INT) -> SOCKET {
    // Call the original function to create the socket
    let call_original = || -> Detour<SocketDescriptor> {
        let socket_result = unsafe { FN_SOCKET(af, type_, protocol) };
        if socket_result == INVALID_SOCKET {
            Detour::Error(std::io::Error::from_raw_os_error(get_last_error()).into())
        } else {
            Detour::Success(socket_result)
        }
    };
    socket(call_original, af, type_, protocol)
        .unwrap_or_bypass_with(|_| unsafe { FN_SOCKET(af, type_, protocol) })
}

/// Windows socket hook for WSASocket (advanced socket creation)
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn wsa_socket_detour(
    af: i32,
    socket_type: i32,
    protocol: i32,
    lpProtocolInfo: *mut u8,
    g: u32,
    dwFlags: u32,
) -> SOCKET {
    let call_original = || -> Detour<SocketDescriptor> {
        let socket_result =
            unsafe { FN_WSA_SOCKET(af, socket_type, protocol, lpProtocolInfo, g, dwFlags) };
        if socket_result == INVALID_SOCKET {
            Detour::Error(std::io::Error::from_raw_os_error(get_last_error()).into())
        } else {
            Detour::Success(socket_result)
        }
    };
    socket(call_original, af, socket_type, protocol).unwrap_or_bypass_with(|_| unsafe {
        FN_WSA_SOCKET(af, socket_type, protocol, lpProtocolInfo, g, dwFlags)
    })
}

#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn wsa_socket_w_detour(
    af: i32,
    socket_type: i32,
    protocol: i32,
    lpProtocolInfo: *mut u16,
    g: u32,
    dwFlags: u32,
) -> SOCKET {
    let call_original = || -> Detour<SOCKET> {
        let socket_result =
            unsafe { FN_WSA_SOCKET_W(af, socket_type, protocol, lpProtocolInfo, g, dwFlags) };
        if socket_result == INVALID_SOCKET {
            Detour::Error(std::io::Error::from_raw_os_error(get_last_error()).into())
        } else {
            Detour::Success(socket_result)
        }
    };
    socket(call_original, af, socket_type, protocol).unwrap_or_bypass_with(|_| unsafe {
        FN_WSA_SOCKET_W(af, socket_type, protocol, lpProtocolInfo, g, dwFlags)
    })
}

/// Windows socket hook for bind
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn bind_detour(s: SOCKET, name: *const SOCKADDR, namelen: INT) -> INT {
    tracing::trace!("bind_detour -> socket: {}, namelen: {}", s, namelen);

    // Define bind function before early returns so it can be reused
    let bind_fn = |addr: *const SOCKADDR, addr_len: INT, reason: &str| -> INT {
        let res = unsafe { FN_BIND(s, addr, addr_len) };

        if res != ERROR_SUCCESS_I32 {
            tracing::error!("bind_detour -> {} failed", reason);
        } else {
            tracing::debug!("bind_detour -> {} succeeded", reason);
        }

        res
    };
    let requested_addr = match unsafe { SocketAddr::try_from_raw(name, namelen) } {
        Some(addr) => addr,
        None => {
            tracing::error!("bind_detour -> failed to convert address");
            return bind_fn(name, namelen, "address parse error");
        }
    };

    tracing::info!(
        "bind_detour -> mirrord binding socket to {}",
        requested_addr
    );

    let mut socket = {
        let mut sockets = SOCKETS
            .lock()
            .expect("bind_detour -> failed to lock sockets for socket retrieval");

        let Some(entry) = sockets.remove(&s) else {
            // fallback / early return when the socket isn’t tracked
            return bind_fn(name, namelen, "non-managed socket");
        };

        entry
    };
    if !matches!(socket.state, SocketState::Initialized) {
        tracing::warn!(
            "bind_detour -> socket {} is not in Initialized state, using original bind",
            s
        );
        return bind_fn(name, namelen, "invalid socket state");
    }

    // Check configuration-based early returns
    let incoming_config = setup().incoming_config();
    if incoming_config.ignore_localhost && requested_addr.ip().is_loopback() {
        tracing::debug!("bind_detour -> ignoring localhost bind");
        return bind_fn(name, namelen, "localhost ignored");
    }

    // Determine the appropriate local binding address
    let local_addr = determine_local_address(requested_addr);

    // Convert to Windows sockaddr for actual binding
    let (local_addr_storage, local_addr_len) = match local_addr.to_sockaddr() {
        Ok((storage, len)) => (storage, len),
        Err(e) => {
            tracing::error!("bind_detour -> failed to convert local address: {}", e);
            return bind_fn(name, namelen, "address conversion error");
        }
    };

    // Attempt primary bind
    let bind_result = bind_fn(
        &local_addr_storage as *const _ as *const SOCKADDR,
        local_addr_len,
        "primary bind",
    );

    // Handle bind failures
    if bind_result != ERROR_SUCCESS_I32 {
        // Check for access denied error which may indicate UAC privilege issues
        // Check if this is a privileged port that requires elevation
        if WindowsError::wsa_last_error() == WSAEACCES && local_addr.port() < IPPORT_RESERVED as u16
        {
            // graceful_exit if process is not elevated.
            require_elevation(&format!(
                "mirrord failed to bind to privileged port {} - insufficient UAC privileges. On Windows, binding to privileged ports (< {}) requires running as Administrator or with elevated UAC privileges. Please restart your application with elevated privileges.",
                local_addr.port(),
                IPPORT_RESERVED
            ));
            // if we are not elevated, this line will not be reachable as require_elevation calls
            // graceful_exit!()
        }

        // return other errors for caller handling
        return bind_result;
    }

    // Get the actual bound address and update socket state
    let actual_bound_addr = unsafe { get_actual_bound_address(s, requested_addr) };
    Arc::get_mut(&mut socket).unwrap().state = SocketState::Bound {
        bound: Bound {
            requested_address: requested_addr,
            address: actual_bound_addr,
        },
        // Note(Daniel): not yet migrated "will_not_trigger_subscription" from unix layer bind
        is_only_bound: false,
    };
    SOCKETS
        .lock()
        .expect("bind_detour -> failed to lock sockets for state update")
        .insert(s, socket);

    tracing::debug!(
        "bind_detour -> socket {} bound locally to {} for requested {}",
        s,
        actual_bound_addr,
        requested_addr
    );

    ERROR_SUCCESS_I32
}

/// Windows socket hook for listen
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn listen_detour(s: SOCKET, backlog: INT) -> INT {
    tracing::trace!("listen_detour -> socket: {}, backlog: {}", s, backlog);

    // Start listening on the local socket first (like Unix layer)
    let listen_fn = |reason: &str| -> INT {
        let res = unsafe { FN_LISTEN(s, backlog) };

        if res != ERROR_SUCCESS_I32 {
            tracing::error!("listen_detour -> {} failed", reason);
        } else {
            tracing::debug!("listen_detour -> {} succeeded", reason);
        }

        res
    };
    let mut socket = {
        let mut sockets = SOCKETS
            .lock()
            .expect("listen_detour -> failed to lock sockets for socket retrieval");

        let Some(entry) = sockets.remove(&s) else {
            // fallback / early return when the socket isn’t tracked
            return listen_fn("non-managed socket");
        };

        entry
    };

    // Check if this socket is managed by mirrord and get bound state
    let bound_state = match socket.state {
        SocketState::Bound {
            bound,
            is_only_bound,
        } if is_only_bound.not() => bound,
        _ => {
            tracing::debug!(
                "listen_detour -> socket {} is not in Bound state, using original listen",
                s
            );
            return listen_fn("invalid socket state");
        }
    };

    let listen_result = listen_fn("expected listen");
    if listen_result != ERROR_SUCCESS_I32 {
        tracing::error!("listen_detour -> listen() failed");
        return listen_result;
    }

    // Check if incoming traffic is enabled
    if matches!(
        setup().incoming_config().mode,
        mirrord_config::feature::network::incoming::IncomingMode::Off
    ) {
        tracing::debug!("listen_detour -> incoming traffic is disabled");
        return listen_result;
    }

    if setup().targetless() {
        tracing::warn!("listen_detour -> running targetless, binding locally instead");
        return listen_result;
    }

    // For Windows socketpair emulation (loopback-bound listener paired with loopback connects),
    // mirrord should leave the socket untouched so the runtime, e.g. python, can manage it locally.
    // Use the requested address to identify synthetic socketpair listeners:
    // they bind to loopback with port 0. Allow normal loopback services on
    // explicit ports to remain managed.
    // On Unix it doesn't matter since socketpair uses AF_UNIX sockets.
    if bound_state.requested_address.ip().is_loopback() && bound_state.requested_address.port() == 0
    {
        tracing::debug!(
            "listen_detour -> skipping subscription for local listener {} -> {}",
            bound_state.requested_address,
            bound_state.address
        );
        return listen_result;
    }

    // Register with the agent for incoming traffic (like Unix layer PortSubscribe)
    let mapped_port = setup()
        .incoming_config()
        .port_mapping
        .get_by_left(&bound_state.requested_address.port())
        .copied()
        .unwrap_or_else(|| bound_state.requested_address.port());

    // Make the request to the agent
    match make_proxy_request_with_response(PortSubscribe {
        listening_on: bound_state.address,
        subscription: setup().incoming_mode().subscription(mapped_port),
    }) {
        Ok(Ok(_)) => {
            // this log message is expected by some E2E tests
            tracing::debug!(
                "daemon subscribed port {}",
                bound_state.requested_address.port()
            );

            Arc::get_mut(&mut socket).unwrap().state = SocketState::Listening(bound_state);
            SOCKETS
                .lock()
                .expect("listen_detour -> failed to lock sockets for state update")
                .insert(s, socket);
            listen_result
        }
        Ok(Err(e)) => {
            tracing::error!("listen_detour -> agent subscription failed: {}", e);

            // Set WSA error and return failure
            unsafe { WSASetLastError(WSAECONNREFUSED) };
            SOCKET_ERROR
        }
        Err(e) => {
            tracing::error!("listen_detour -> failed to make proxy request: {}", e);

            // Set WSA error and return failure
            unsafe { WSASetLastError(WSAECONNREFUSED) };
            SOCKET_ERROR
        }
    }
}

/// Windows socket hook for connect
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn connect_detour(s: SOCKET, name: *const SOCKADDR, namelen: INT) -> INT {
    tracing::trace!("connect_detour -> socket: {}, namelen: {}", s, namelen);

    let connect_fn = |addr: SockAddr| {
        let result = unsafe { FN_CONNECT(s, addr.as_ptr() as *const _, addr.len()) };
        log_connection_result(result, "connect_detour", addr);
        ConnectResult::from(result)
    };

    match ops::connect(s, name, namelen, "connect_detour", connect_fn) {
        Err(HookError::ConnectError(ConnectError::AddressUnreachable(_))) => {
            return SOCKET_ERROR;
        }
        Err(e) => {
            tracing::debug!(
                "connect_detour -> socket {} not managed, using original. err: {}",
                s,
                e
            );
        }
        Ok(connect_result) => {
            return connect_result.result();
        }
    }

    // fallback to original
    unsafe { FN_CONNECT(s, name, namelen) }
}

/// Windows socket hook for accept
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn accept_detour(
    s: SOCKET,
    addr: *mut SOCKADDR,
    addrlen: *mut INT,
) -> SOCKET {
    tracing::trace!("accept_detour -> socket: {}", s);

    // Call original accept first
    let accepted_socket = unsafe { FN_ACCEPT(s, addr, addrlen) };
    if accepted_socket == INVALID_SOCKET {
        tracing::error!("accept_detour -> original accept failed");
        return accepted_socket;
    }
    tracing::info!(
        "accept_detour -> accepted socket {} from mirrord-managed listener",
        accepted_socket
    );

    // Wrap the accepted socket in RAII wrapper for automatic cleanup on error
    let auto_close_socket = AutoCloseSocket::new(accepted_socket);
    let (domain, protocol, type_, port, listener_address) = {
        let sockets = SOCKETS
            .lock()
            .expect("accept_detour -> failed to lock sockets for socket retrieval");

        let Some(socket) = sockets.get(&s) else {
            tracing::warn!(
                "accept_detour -> socket {} is not tracked, using original accept",
                s
            );
            // fallback / early return when the socket isn’t tracked
            return auto_close_socket.release();
        };

        match &socket.state {
            SocketState::Listening(Bound {
                requested_address,
                address,
            }) => (
                socket.domain,
                socket.protocol,
                socket.type_,
                requested_address.port(),
                *address,
            ),
            _ => {
                tracing::debug!(
                    "accept_detour -> socket {} is not in Bound state, using original accept",
                    s
                );
                return auto_close_socket.release();
            }
        }
    };

    // Get peer address from the accepted connection (this will be intproxy's address)
    let peer_address = match utils::get_peer_address_from_socket(auto_close_socket.get()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("accept_detour -> failed to get peer address: {}", e);
            // Socket will be automatically closed by AutoCloseSocket::drop
            unsafe { WSASetLastError(WSAECONNABORTED) };
            return INVALID_SOCKET;
        }
    };

    // Make ConnMetadataRequest to get the real remote source address
    let ConnMetadataResponse {
        remote_source,
        local_address,
    } = match make_proxy_request_with_response(ConnMetadataRequest {
        listener_address,
        peer_address,
    }) {
        Ok(res) => {
            tracing::info!(
                "accept_detour -> got metadata: remote_source={}, local_address={}",
                res.remote_source,
                res.local_address
            );
            res
        }
        Err(e) => {
            tracing::error!("accept_detour -> failed to get connection metadata: {}", e);
            // Like Unix layer, fail the accept if we can't get metadata
            unsafe { WSASetLastError(WSAECONNABORTED) };
            return INVALID_SOCKET;
        }
    };

    // Register the accepted socket with mirrord
    let Ok(socket_kind) = socket_kind_from_type(type_) else {
        tracing::warn!("Failed to create socket kind");
        return auto_close_socket.release();
    };
    let state = SocketState::Connected(Connected {
        connection_id: None,
        remote_address: remote_source.into(),
        local_address: Some(SocketAddr::new(local_address, port).into()),
        layer_address: None,
    });
    let new_socket = UserSocket::new(domain, type_, protocol, state, socket_kind);

    // fill_address - Fill in the address structure with the real remote address (not intproxy's
    // address)
    if !addr.is_null() && !addrlen.is_null() {
        match unsafe { remote_source.copy_to(addr, addrlen) } {
            Ok(()) => {
                tracing::trace!(
                    "accept_detour -> filled address with real remote source: {}",
                    remote_source
                );
            }
            Err(e) => {
                tracing::warn!("accept_detour -> failed to fill address: {}", e);
            }
        }
    }

    SOCKETS
        .lock()
        .expect("accept_detour -> failed to lock sockets for state update")
        .insert(accepted_socket, Arc::new(new_socket));

    // Success! Release the socket from automatic cleanup and return it
    auto_close_socket.release()
}

/// Windows socket hook for getsockname
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn getsockname_detour(
    s: SOCKET,
    name: *mut SOCKADDR,
    namelen: *mut INT,
) -> INT {
    tracing::trace!("getsockname_detour -> socket: {}", s);
    let getsockname_fn = || {
        unsafe { FN_GETSOCKNAME(s, name, namelen) }
    };

    let socket = match SOCKETS
        .lock()
        .expect("getsockname_detour -> failed to lock sockets for socket retrieval")
        .get(&s)
    {
        Some(sock) => sock.clone(),
        None => {
            tracing::warn!("getsockname_detour -> failed to get socket: {}", s);
            return getsockname_fn();
        }
    };

    let local_address: Option<SocketAddr> = match &socket.state {
        SocketState::Connected(Connected {
            local_address: Some(addr),
            ..
        }) => Some(addr.clone().try_into().unwrap()),
        SocketState::Connected(Connected {
            connection_id: Some(id),
            ..
        }) => {
            match make_proxy_request_with_response(OutgoingConnMetadataRequest { conn_id: *id }) {
                Ok(Some(res)) => Some(res.in_cluster_address),
                Ok(None) => {
                    tracing::error!(id, "Protocol: could not locate outgoing metadata");
                    None
                }
                Err(e) => {
                    tracing::error!(?e, id, "Proxy: Error getting outgoing metadata");
                    None
                }
            }
        }
        SocketState::Bound {
            bound: Bound {
                requested_address,
                address,
            },
            ..
        }
        | SocketState::Listening(Bound {
            requested_address,
            address,
        }) => Some(if requested_address.port() == 0 {
            SocketAddr::new(requested_address.ip(), address.port())
        } else {
            *requested_address
        }),

        SocketState::Initialized | SocketState::Connected(_) => {
            // For other managed socket states, fall back to original
            tracing::trace!(
                "getsockname_detour -> managed socket not in bound/connected state, using original"
            );
            None
        }
    };

    // fill_address - Fill in the address structure with the mirrord local address
    if let Some(local_address) = local_address {
        match unsafe { local_address.copy_to(name, namelen) } {
            Ok(()) => {
                tracing::trace!("getsockname_detour -> returned mirrord local address");
                // Success
                return ERROR_SUCCESS_I32;
            }

            Err(err) => {
                tracing::debug!(
                    "getsockname_detour -> failed to convert layer address: {}",
                    err
                );

                match err {
                    WindowsError::WinSock(error_code) => unsafe {
                        WSASetLastError(error_code);
                    },

                    WindowsError::Windows(error_code) => {
                        tracing::warn!(
                            "getsockname_detour -> unexpected windows error converting layer address: error {}",
                            error_code
                        );
                    }
                };

                return SOCKET_ERROR;
            }
        }
    }

    // Fall back to original function for non-managed sockets or errors
    getsockname_fn()
}

/// Windows socket hook for getpeername
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn getpeername_detour(
    s: SOCKET,
    name: *mut SOCKADDR,
    namelen: *mut INT,
) -> INT {
    tracing::trace!("getpeername_detour -> socket: {}", s);

    // Check if this socket is managed and get connected addresses
    if let Some((remote_addr, _, _)) = get_connected_addresses(s) {
        // Return the remote address for connected sockets

        match unsafe { remote_addr.copy_to(name, namelen) } {
            Ok(()) => {
                tracing::trace!("getpeername_detour -> returned mirrord remote address");
                // Success
                return ERROR_SUCCESS_I32;
            }

            Err(err) => {
                tracing::debug!(
                    "getpeername_detour -> failed to convert remote address: {}",
                    err
                );

                match err {
                    WindowsError::WinSock(error_code) => unsafe {
                        WSASetLastError(error_code);
                    },

                    WindowsError::Windows(error_code) => {
                        tracing::warn!(
                            "getpeername_detour -> unexpected windows error converting remote address: error {}",
                            error_code
                        );
                    }
                };

                return SOCKET_ERROR;
            }
        }
    } else if is_socket_managed(s) {
        tracing::trace!(
            "getpeername_detour -> managed socket not in connected state, using original"
        );
    }

    // Fall back to original function for non-managed sockets or errors
    unsafe { FN_GETPEERNAME(s, name, namelen) }
}

/// Socket management detour for WSAIoctl - intercepts extension lookups
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn wsa_ioctl_detour(
    s: SOCKET,
    dwIoControlCode: u32,
    lpvInBuffer: *mut c_void,
    cbInBuffer: u32,
    lpvOutBuffer: *mut c_void,
    cbOutBuffer: u32,
    lpcbBytesReturned: *mut u32,
    lpOverlapped: *mut WSAOVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> INT {
    let result = unsafe {
        FN_WSA_IOCTL(
            s,
            dwIoControlCode,
            lpvInBuffer,
            cbInBuffer,
            lpvOutBuffer,
            cbOutBuffer,
            lpcbBytesReturned,
            lpOverlapped,
            lpCompletionRoutine,
        )
    };

    if result == ERROR_SUCCESS_I32 && dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER {
        unsafe {
            hook_connectex_extension(
                lpvInBuffer,
                cbInBuffer,
                lpvOutBuffer,
                cbOutBuffer,
                Some(connectex_detour),
            );
        }
    }

    result
}

/// Windows socket hook for ConnectEx (overlapped connect)
/// This function properly handles libuv's expectations for overlapped I/O completion
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn connectex_detour(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: INT,
    lpSendBuffer: *mut c_void,
    dwSendDataLength: u32,
    lpdwBytesSent: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
) -> BOOL {
    tracing::debug!(
        "connectex_detour -> socket: {}, namelen: {}, send_length: {}, overlapped: {:?}",
        s,
        namelen,
        dwSendDataLength,
        lpOverlapped
    );

    let original_connectex = match get_connectex_original() {
        Some(ptr) => ptr,
        None => {
            tracing::error!("connectex_detour -> original ConnectEx pointer not initialized");
            unsafe { WSASetLastError(WSAEFAULT) };
            return FALSE;
        }
    };

    let socket_addr = match unsafe { SocketAddr::try_from_raw(name, namelen) } {
        Some(addr) => addr,
        None => {
            tracing::error!(
                "connectex_detour -> failed to convert raw sockaddr for socket {}",
                s
            );
            unsafe { WSASetLastError(WSAEFAULT) };
            return FALSE;
        }
    };
    let raw_addr = SockAddr::from(socket_addr);

    // Check if this socket is managed
    let is_managed = is_socket_managed(s);

    // Unified connect function for both managed and unmanaged sockets
    let connect_fn = |addr: SockAddr| {
        let addr_description = if is_managed {
            format!("proxy at {:?}", addr)
        } else {
            format!("target at {:?}", addr)
        };

        tracing::debug!(
            "connectex_detour connect_fn -> establishing connection for socket {} to {}",
            s,
            addr_description
        );

        // Connect using original ConnectEx
        let result = unsafe {
            original_connectex(
                s,
                addr.as_ptr() as *const SOCKADDR,
                addr.len(),
                lpSendBuffer,
                dwSendDataLength,
                lpdwBytesSent,
                lpOverlapped,
            )
        };

        let last_error = unsafe { WSAGetLastError() };

        tracing::debug!(
            "connectex_detour connect_fn -> original ConnectEx to {} result: {}, last_error: {}",
            addr_description,
            result,
            last_error
        );

        // Return the result from ConnectEx - layer-lib will handle the conversion
        if result != 0 {
            ConnectResult::new(ERROR_SUCCESS_I32, None)
        } else {
            ConnectResult::new(SOCKET_ERROR, Some(last_error))
        }
    };

    // For managed sockets, use connect which will call connect_fn with proxy
    // address
    if is_managed {
        match ops::connect(s, name, namelen, "connectex_detour", connect_fn) {
            Ok(connect_result) => {
                tracing::debug!(
                    "connectex_detour -> proxy connection result: {:?}",
                    connect_result
                );

                // Handle the proxy connection result
                let error_opt = connect_result.error();
                let result_code: i32 = connect_result.into();
                tracing::debug!(
                    "connectex_detour -> proxy connection result: {}",
                    result_code
                );

                if result_code == ERROR_SUCCESS_I32 {
                    return TRUE;
                } else if error_opt == Some(WSA_IO_PENDING) {
                    tracing::info!(
                        "connectex_detour -> socket {} ConnectEx to proxy returned WSA_IO_PENDING, attempting immediate completion check",
                        s
                    );
                    unsafe {
                        WSASetLastError(WSA_IO_PENDING);
                    }
                    return FALSE;
                } else {
                    // For async operations, set the last error and return FALSE
                    if let Some(error) = error_opt {
                        unsafe {
                            WSASetLastError(error);
                        }
                        tracing::debug!(
                            "connectex_detour -> set last error to {} for async operation",
                            error
                        );
                    }
                    return FALSE;
                }
            }
            Err(HookError::ConnectError(ConnectError::AddressUnreachable(e))) => {
                tracing::error!(
                    "connectex_detour -> socket {} connect target {:?} is unreachable: {}",
                    s,
                    raw_addr,
                    e
                );
                unsafe { WSASetLastError(WSAEFAULT) };
                return FALSE;
            }
            Err(e) => {
                tracing::debug!(
                    "connectex_detour -> socket {} proxy connection setup failed, err: {}",
                    s,
                    e
                );
                // Fall back to direct connection using the same connect_fn
            }
        }
    } else {
        tracing::debug!("connectex_detour -> socket {} not managed", s);
        // For unmanaged sockets, call connect_fn directly with the original target address
    }

    tracing::debug!("connectex_detour -> using original for socket {}", s);
    let connect_result = connect_fn(raw_addr);
    let error_opt = connect_result.error();
    let result_code: i32 = connect_result.into();

    if result_code == ERROR_SUCCESS_I32 {
        TRUE
    } else {
        // Set last error if provided and return FALSE
        if let Some(error) = error_opt {
            unsafe {
                WSASetLastError(error);
            }
        }
        FALSE
    }
}

/// Windows socket hook for WSAConnect (asynchronous connect)
/// Node.js uses this for non-blocking connect operations
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn wsa_connect_detour(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: INT,
    lpCallerData: *mut u8,
    lpCalleeData: *mut u8,
    lpSQOS: *mut u8,
    lpGQOS: *mut u8,
) -> INT {
    tracing::trace!("wsa_connect_detour -> socket: {}, namelen: {}", s, namelen);

    let connect_fn = |addr: SockAddr| {
        // Call the original function with the prepared sockaddr
        let result = unsafe {
            FN_WSA_CONNECT(
                s,
                addr.as_ptr() as *const _,
                addr.len(),
                lpCallerData,
                lpCalleeData,
                lpSQOS,
                lpGQOS,
            )
        };
        log_connection_result(result, "wsa_connect_detour", addr);
        ConnectResult::from(result)
    };

    let socket_addr = match unsafe { SocketAddr::try_from_raw(name, namelen) } {
        Some(addr) => addr,
        None => {
            tracing::error!(
                "wsa_connect_detour -> failed to convert raw sockaddr for socket {}",
                s
            );
            return SOCKET_ERROR;
        }
    };
    let raw_addr = SockAddr::from(socket_addr);

    match ops::connect(s, name, namelen, "wsa_connect_detour", connect_fn) {
        Err(HookError::ConnectError(ConnectError::AddressUnreachable(e))) => {
            tracing::error!(
                "wsa_connect_detour -> socket {} connect target {:?} is unreachable: {}",
                s,
                raw_addr,
                e
            );
            return SOCKET_ERROR;
        }
        Err(_) => {
            tracing::debug!(
                "wsa_connect_detour -> socket {} not managed, using original",
                s
            );
        }
        Ok(connect_result) => {
            return connect_result.result();
        }
    }

    // Fallback to original function
    let connect_res = connect_fn(raw_addr);
    connect_res.result()
}

/// Windows socket hook for WSASendTo (asynchronous UDP send)
/// Node.js uses this for overlapped UDP operations
/// This implementation uses the shared layer-lib sendto functionality to handle DNS resolution
/// and socket routing while preserving compatibility with Windows overlapped I/O.
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn wsa_send_to_detour(
    s: SOCKET,
    lpBuffers: *mut u8,
    dwBufferCount: u32,
    lpNumberOfBytesSent: *mut u32,
    dwFlags: u32,
    lpTo: *const SOCKADDR,
    iTolen: INT,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> INT {
    tracing::debug!(
        "wsa_send_to_detour -> socket: {}, buffer_count: {}, to_len: {}",
        s,
        dwBufferCount,
        iTolen
    );

    // Helper function to consolidate all fallback calls to original WSASendTo
    let fallback_to_original = |reason: &str| {
        tracing::debug!("wsa_send_to_detour -> falling back to original: {}", reason);
        unsafe {
            FN_WSA_SEND_TO(
                s,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpTo,
                iTolen,
                lpOverlapped,
                lpCompletionRoutine,
            )
        }
    };

    if lpNumberOfBytesSent.is_null() {
        return fallback_to_original("null lpNumberOfBytesSent");
    }

    // From Docs: (https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto#remarks)
    // The WSASendTo function is normally used on a connectionless socket specified by s to send a
    // datagram contained in one or more buffers to a specific peer socket identified by the lpTo
    // parameter. Even if the connectionless socket has been previously connected using the
    // connect function to a specific address, lpTo overrides the destination address for that
    // particular datagram only. On a connection-oriented socket, the lpTo and iToLen parameters
    // are ignored; in this case, the WSASendTo is equivalent to WSASend.
    if lpTo.is_null() || iTolen <= 0 {
        // For connection-oriented sockets or when no destination is specified,
        // WSASendTo is equivalent to WSASend
        return unsafe {
            WSASend(
                s,
                lpBuffers as LPWSABUF,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpOverlapped,
                lpCompletionRoutine,
            )
        };
    }

    // Convert Windows destination address to cross-platform format
    let raw_destination = match unsafe { SocketAddr::try_from_raw(lpTo as *const _, iTolen as _) } {
        Some(addr) => addr,
        None => unreachable!(),
    };

    // Windows WSASendTo function wrapper for layer-lib
    let call_original = |sockfd: SOCKET,
                            addr: SockAddr|
        -> Detour<INT> {
        // Create a WSABUF for the single buffer using our helper
        let mut bytes_sent = 0u32;
        let result = unsafe {
            FN_WSA_SEND_TO(
                sockfd,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                addr.as_ptr() as *const SOCKADDR,
                addr.len() as INT,
                lpOverlapped,
                lpCompletionRoutine,
            )
        };

        if result == ERROR_SUCCESS_I32 {
            // Success - update bytes sent if caller provided pointer
            unsafe { *lpNumberOfBytesSent = bytes_sent };
            Detour::Success(result.try_into().unwrap())
        } else {
            Detour::Error(SendToError::SendFailed(result.try_into().unwrap()).into())
        }
    };

    send_to(call_original, s, raw_destination)
        .unwrap_or_bypass_with(|_| unsafe { fallback_to_original("layer-lib sendto bypass") })
}

/// Windows winsock hook for gethostname
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn gethostname_detour(name: *mut i8, namelen: INT) -> INT {
    tracing::debug!("gethostname_detour called with namelen: {}", namelen);
    // IN namelen is not writable, as a workaround we work on local variable we'll just ditch
    let mut namelen_mut = namelen as u32;
    let namelen_ptr: *mut u32 = &mut namelen_mut;
    unsafe {
        // gethostname is similar to hostname_ansi except:
        //     * different ret vals
        //     * GLE (GetLastError) -> WSAGLE
        handle_hostname_ansi(
            name,
            namelen_ptr,
            || FN_GETHOSTNAME(name, namelen),
            || remote_hostname_string(true),
            "gethostname",
            ERROR_BUFFER_OVERFLOW,
            // If no error occurs, gethostname returns zero. Otherwise, it returns SOCKET_ERROR
            //  and a specific error code can be retrieved by calling WSAGetLastError.
            (ERROR_SUCCESS_I32, SOCKET_ERROR),
        )
    }
}

/// Windows kernel32 hook for GetComputerNameA
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn get_computer_name_a_detour(lpBuffer: *mut i8, nSize: *mut u32) -> i32 {
    unsafe {
        handle_hostname_ansi(
            lpBuffer,
            nSize,
            || FN_GET_COMPUTER_NAME_A(lpBuffer, nSize),
            || remote_hostname_string(true),
            "GetComputerNameA",
            ERROR_BUFFER_OVERFLOW,
            // If the function succeeds, the return value is a nonzero value.
            // If the function fails, the return value is zero.
            (1, 0),
        )
    }
}

/// Windows kernel32 hook for GetComputerNameW
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn get_computer_name_w_detour(lpBuffer: *mut u16, nSize: *mut u32) -> BOOL {
    unsafe {
        handle_hostname_unicode(
            lpBuffer,
            nSize,
            || FN_GET_COMPUTER_NAME_W(lpBuffer, nSize),
            || remote_hostname_string(true),
            "GetComputerNameW",
            ERROR_BUFFER_OVERFLOW,
        )
    }
}

/// Windows kernel32 hook for GetComputerNameExA
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn get_computer_name_ex_a_detour(
    name_type: u32,
    lpBuffer: *mut i8,
    nSize: *mut u32,
) -> i32 {
    tracing::debug!(
        "GetComputerNameExA hook called with name_type: {}",
        name_type
    );
    // supported name types for hostname interception
    let should_intercept = matches!(
        name_type,
        ComputerNameDnsHostname
            | ComputerNameDnsFullyQualified
            | ComputerNamePhysicalDnsHostname
            | ComputerNamePhysicalDnsFullyQualified
            | ComputerNameNetBIOS
            | ComputerNamePhysicalNetBIOS
    );

    if should_intercept {
        return handle_hostname_ansi(
            lpBuffer,
            nSize,
            || unsafe { FN_GET_COMPUTER_NAME_EX_A(name_type, lpBuffer, nSize) },
            || hostname::get_hostname_for_name_type(name_type),
            "GetComputerNameExA",
            ERROR_MORE_DATA,
            // If the function succeeds, the return value is a nonzero value.
            // If the function fails, the return value is zero.
            (1, 0),
        );
    }

    // forward non-supported name_types to original func
    tracing::debug!(
        "GetComputerNameExW: unsupported name_type {}, falling back to original",
        name_type
    );
    return unsafe { FN_GET_COMPUTER_NAME_EX_A(name_type, lpBuffer, nSize) };
}

/// Windows kernel32 hook for GetComputerNameExW
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn get_computer_name_ex_w_detour(
    name_type: u32,
    lpBuffer: *mut u16,
    nSize: *mut u32,
) -> BOOL {
    // supported name types for hostname interception
    let should_intercept = matches!(
        name_type,
        ComputerNameDnsHostname
            | ComputerNameDnsFullyQualified
            | ComputerNamePhysicalDnsHostname
            | ComputerNamePhysicalDnsFullyQualified
            | ComputerNameNetBIOS
            | ComputerNamePhysicalNetBIOS
    );

    if should_intercept {
        return handle_hostname_unicode(
            lpBuffer,
            nSize,
            || unsafe { FN_GET_COMPUTER_NAME_EX_W(name_type, lpBuffer, nSize) },
            || hostname::get_hostname_for_name_type(name_type),
            "GetComputerNameExW",
            ERROR_MORE_DATA,
        );
    }

    // forward non-supported name_types to original func
    tracing::debug!(
        "GetComputerNameExW: unsupported name_type {}, falling back to original",
        name_type
    );
    return unsafe { FN_GET_COMPUTER_NAME_EX_W(name_type, lpBuffer, nSize) };
}

/// Hook for gethostbyname to handle DNS resolution of our modified hostname
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn gethostbyname_detour(name: *const i8) -> *mut HOSTENT {
    let fallback_to_original = || unsafe { FN_GETHOSTBYNAME(name) };

    if name.is_null() {
        tracing::debug!("gethostbyname: name is null, calling original");
        return fallback_to_original();
    }

    // SAFETY: Validate the string pointer before dereferencing
    let hostname_cstr = match unsafe { std::ffi::CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::debug!("gethostbyname: invalid UTF-8 in hostname, calling original");
            return fallback_to_original();
        }
    };

    tracing::debug!("gethostbyname: resolving hostname: {}", hostname_cstr);

    // Check if this is our remote hostname
    if is_remote_hostname(hostname_cstr.to_string()) {
        tracing::debug!(
            "gethostbyname: intercepting resolution for our hostname: {}",
            hostname_cstr
        );
    }

    // Check if we should resolve this hostname remotely using the DNS selector
    if let Detour::Bypass(reason) = setup()
        .dns_selector()
        .check_query(hostname_cstr.as_ref(), 0)
    {
        tracing::debug!(
            ?reason,
            "DNS selector check returned local for '{}'",
            hostname_cstr,
        );
        return fallback_to_original();
    }

    // Try to resolve the hostname using mirrord's remote DNS resolution
    match remote_dns_resolve_via_proxy(hostname_cstr) {
        Ok(results) => {
            if let Some((name, ip)) = results.first() {
                // Use the first IP address from the results
                tracing::debug!(
                    "Remote DNS resolution successful: {} -> {}",
                    hostname_cstr,
                    ip
                );

                // Create a proper HOSTENT structure from the resolved data using thread-local
                // storage This mimics WinSock's behavior where each thread has its
                // own HOSTENT buffer
                match create_thread_local_hostent(name.clone(), *ip) {
                    Ok(hostent_ptr) => return hostent_ptr,
                    Err(e) => {
                        tracing::warn!(
                            "Failed to create HOSTENT structure for {}: {:?}",
                            hostname_cstr,
                            e
                        );
                        // Fall back to original function
                    }
                }
            } else {
                tracing::warn!(
                    "Remote DNS resolution returned empty results for {}",
                    hostname_cstr
                );
            }
            // fallback to original
        }
        Err(e) => {
            tracing::warn!("Remote DNS resolution failed for {}: {}", hostname_cstr, e);
            // fallback to original
        }
    }

    // For all other hostnames or if our hostname resolution fails, call original function
    tracing::debug!(
        "gethostbyname: calling original function for hostname: {}",
        hostname_cstr
    );
    return fallback_to_original();
}

/// Hook for getaddrinfo to handle DNS resolution with full mirrord functionality
///
/// This follows the same pattern as the Unix layer but uses Windows types and calling conventions.
/// It converts Windows ADDRINFOA structures and makes DNS requests through the mirrord agent.
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn getaddrinfo_detour(
    raw_node: *const u8,
    raw_service: *const u8,
    raw_hints: *const ADDRINFOA,
    out_addr_info: *mut *mut ADDRINFOA,
) -> INT {
    let node_opt = match Option::from(raw_node) {
        Some(ptr) if !ptr.is_null() => {
            Some(unsafe { str_win::u8_buffer_to_string(PCSTR(ptr).as_bytes()) })
        }
        _ => None,
    };
    tracing::warn!("getaddrinfo_detour called for hostname: {:?}", node_opt);

    let service_opt = match Option::from(raw_service) {
        Some(ptr) if !ptr.is_null() => {
            Some(unsafe { str_win::u8_buffer_to_string(PCSTR(ptr).as_bytes()) })
        }
        _ => None,
    };

    let hints_ref = unsafe { raw_hints.as_ref() };

    // temporary Detour workaround until WIN-85
    let managed_addr_info = match getaddrinfo::<ADDRINFOA>(node_opt, service_opt, hints_ref) {
        Detour::Success(info) => info,
        Detour::Bypass(bypass) => {
            // Fall back to original Windows getaddrinfo
            tracing::debug!(
                ?bypass,
                "getaddrinfo: falling back to original Windows function"
            );
            return unsafe {
                FN_GETADDRINFO(
                    raw_node,
                    raw_service,
                    raw_hints,
                    out_addr_info,
                )
            };
        }
        Detour::Error(err) => {
            tracing::error!(?err, "getaddrinfo failed");
            return err.into();
        }
    };

    // Store the managed result pointer and move the object to MANAGED_ADDRINFO
    let addr_ptr = managed_addr_info.as_ptr();
    MANAGED_ADDRINFO
        .lock()
        .expect("getaddrinfo: MANAGED_ADDRINFO was poisoned")
        .insert(addr_ptr as usize, ManagedAddrInfoAny::A(managed_addr_info));
    unsafe { *out_addr_info = addr_ptr };

    ERROR_SUCCESS_I32
}

/// Hook for GetAddrInfoW (Unicode version) to handle DNS resolution
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn getaddrinfow_detour(
    node_name: *const u16,
    service_name: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> INT {
    tracing::warn!("GetAddrInfoW_detour called");

    let node_opt = match Option::from(node_name) {
        Some(ptr) if !ptr.is_null() => unsafe {
            Some(str_win::u16_buffer_to_string(PCWSTR(ptr).as_wide()))
        },
        _ => None,
    };
    tracing::warn!("GetAddrInfoW_detour called for hostname: {:?}", node_opt);

    let service_opt = match Option::from(service_name) {
        Some(ptr) if !ptr.is_null() => unsafe {
            Some(str_win::u16_buffer_to_string(PCWSTR(ptr).as_wide()))
        },
        _ => None,
    };

    let hints_ref = unsafe { hints.as_ref() };

    // temporary Detour workaround until WIN-85
    let managed_addr_info = match getaddrinfo::<ADDRINFOW>(node_opt.clone(), service_opt, hints_ref)
    {
        Detour::Success(info) => info,
        Detour::Bypass(bypass) => {
            // For all other hostnames or if conversion fails, call original function
            tracing::debug!(
                ?bypass,
                "GetAddrInfoW: calling original function for hostname: {:?}",
                node_opt
            );
            return unsafe {
                FN_GETADDRINFOW(node_name, service_name, hints, result)
            };
        }
        Detour::Error(err) => {
            tracing::error!(?err, "GetAddrInfoW failed");
            return err.into();
        }
    };

    // Store the managed result pointer and move the object to MANAGED_ADDRINFO
    let addr_ptr = managed_addr_info.as_ptr();
    MANAGED_ADDRINFO
        .lock()
        .expect("getaddrinfo: MANAGED_ADDRINFO was poisoned")
        .insert(addr_ptr as usize, ManagedAddrInfoAny::W(managed_addr_info));
    unsafe { *result = addr_ptr };

    ERROR_SUCCESS_I32
}

/// Deallocates ADDRINFOA structures that were allocated by our getaddrinfo_detour.
///
/// This follows the same pattern as the Unix layer - it checks if the structure
/// was allocated by us and frees it properly, or calls the original freeaddrinfo if it wasn't ours.
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn freeaddrinfo_t_detour(addrinfo: *mut ADDRINFOW) {
    unsafe {
        // note: supports both ADDRINFOA and ADDRINFOW,
        //  the proper dealloc will be called
        if !free_managed_addrinfo(addrinfo) {
            // Not one of ours - call original freeaddrinfo
            FN_FREEADDRINFO_T(addrinfo);
        }
    }
}

/// Data transfer detour for sendto() - sends data to a socket with destination address
///
/// This implementation uses the shared layer-lib sendto functionality to handle DNS resolution
/// and socket routing while preserving compatibility with Windows applications.
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn sendto_detour(
    s: SOCKET,
    buf: *const i8,
    len: INT,
    flags: INT,
    to: *const SOCKADDR,
    tolen: INT,
) -> INT {
    tracing::debug!(
        "sendto_detour -> socket: {}, len: {}, tolen: {}",
        s,
        len,
        tolen
    );

    // Windows sendto function wrapper
    let call_original = |sockfd: SOCKET,
                         addr: SockAddr|
     -> Detour<INT> {
        Detour::Success(unsafe {
            FN_SENDTO(
                sockfd,
                buf,
                len,
                flags,
                addr.as_ptr() as *const SOCKADDR,
                addr.len() as INT,
            )
        })
    };

    // Helper function to consolidate all fallback calls to original sendto
    let fallback_to_original = |reason: &str| -> INT {
        tracing::debug!("sendto_detour -> falling back to original: {}", reason);
        unsafe { FN_SENDTO(s, buf, len, flags, to, tolen) }
    };

    // Convert Windows parameters to cross-platform format
    let raw_destination = match unsafe { SocketAddr::try_from_raw(to as *const _, tolen as _) } {
        Some(addr) => addr,
        None => {
            return fallback_to_original("failed to parse destination address");
        }
    };

    send_to(call_original, s, raw_destination)
        .unwrap_or_bypass_with(|_| fallback_to_original("layer-lib sendto bypass"))
}

/// Socket management detour for closesocket() - closes a socket
#[hook_guard_fn]
#[mirrord_layer_macro::instrument(level = "trace", ret)]
unsafe extern "system" fn closesocket_detour(s: SOCKET) -> INT {
    let res = unsafe { FN_CLOSESOCKET(s) };

    if let Some(socket) = SOCKETS.lock().expect("SOCKETS lock failed").remove(&s)
        && matches!(socket.state, SocketState::Listening(_))
    {
        // Call close() method to send PortUnsubscribe if socket was listening
        socket.close();
    }

    res
}

/// Initialize socket hooks by setting up detours for Windows socket functions
pub fn initialize_hooks(
    guard: &mut DetourEngineGuard<'static>,
    setup: &LayerSetup,
) -> LayerResult<()> {
    // Ensure winsock libraries are loaded before attempting to hook them
    // This prevents issues with Python's _socket.pyd or other dynamic loaders
    // ensure_winsock_libraries_loaded()?;

    let dns_enabled = setup.dns_hooks_enabled();
    let socket_enabled = setup.socket_hooks_enabled();
    let network_config = setup.network_config();

    // Early return if no socket features are enabled
    if !dns_enabled && !socket_enabled {
        tracing::info!("All socket hooks disabled by configuration");
        return Ok(());
    }

    tracing::info!(
        "Initializing socket hooks (DNS: {}, Sockets: {})",
        dns_enabled,
        socket_enabled
    );

    // DNS resolution hooks (if DNS is enabled)
    if dns_enabled {
        tracing::info!("Enabling DNS resolution hooks");

        apply_hook!(
            guard,
            "ws2_32",
            "gethostbyname",
            gethostbyname_detour,
            FnGethostbyname,
            FN_GETHOSTBYNAME
        )?;

        apply_hook!(
            guard,
            "ws2_32",
            "getaddrinfo",
            getaddrinfo_detour,
            FnGetaddrinfo,
            FN_GETADDRINFO
        )?;

        apply_hook!(
            guard,
            "ws2_32",
            "GetAddrInfoW",
            getaddrinfow_detour,
            FnGetaddrinfow,
            FN_GETADDRINFOW
        )?;

        // Note: FreeAddrInfoW is used for both ADDRINFOA and ADDRINFOW deallocation
        apply_hook!(
            guard,
            "ws2_32",
            "FreeAddrInfoW",
            freeaddrinfo_t_detour,
            FnFreeaddrinfo_t,
            FN_FREEADDRINFO_T
        )?;

        // Hostname hooks
        apply_hook!(
            guard,
            "ws2_32",
            "gethostname",
            gethostname_detour,
            FnGethostname,
            FN_GETHOSTNAME
        )?;

        apply_hook!(
            guard,
            "kernel32",
            "GetComputerNameExW",
            get_computer_name_ex_w_detour,
            FnGet_computer_name_ex_w,
            FN_GET_COMPUTER_NAME_EX_W
        )?;

        apply_hook!(
            guard,
            "kernel32",
            "GetComputerNameExA",
            get_computer_name_ex_a_detour,
            FnGet_computer_name_ex_a,
            FN_GET_COMPUTER_NAME_EX_A
        )?;

        apply_hook!(
            guard,
            "kernel32",
            "GetComputerNameA",
            get_computer_name_a_detour,
            FnGet_computer_name_a,
            FN_GET_COMPUTER_NAME_A
        )?;

        apply_hook!(
            guard,
            "kernel32",
            "GetComputerNameW",
            get_computer_name_w_detour,
            FnGet_computer_name_w,
            FN_GET_COMPUTER_NAME_W
        )?;
    } else {
        tracing::info!("DNS hooks disabled by configuration");
    }

    // Socket operation hooks (if socket features are enabled)
    if socket_enabled {
        tracing::info!("Enabling socket operation hooks");

        // Core socket operations (always needed if sockets enabled)
        apply_hook!(
            guard,
            "ws2_32",
            "socket",
            socket_detour,
            FnSocket,
            FN_SOCKET
        )?;

        apply_hook!(
            guard,
            "ws2_32",
            "WSASocketA",
            wsa_socket_detour,
            FnWsa_socket,
            FN_WSA_SOCKET
        )?;

        apply_hook!(
            guard,
            "ws2_32",
            "WSASocketW",
            wsa_socket_w_detour,
            FnWsa_socket_w,
            FN_WSA_SOCKET_W
        )?;

        // Socket lifecycle management
        apply_hook!(
            guard,
            "ws2_32",
            "closesocket",
            closesocket_detour,
            FnClosesocket,
            FN_CLOSESOCKET
        )?;

        // Socket information hooks
        apply_hook!(
            guard,
            "ws2_32",
            "getsockname",
            getsockname_detour,
            FnGetsockname,
            FN_GETSOCKNAME
        )?;

        apply_hook!(
            guard,
            "ws2_32",
            "getpeername",
            getpeername_detour,
            FnGetpeername,
            FN_GETPEERNAME
        )?;

        // I/O control
        apply_hook!(
            guard,
            "ws2_32",
            "WSAIoctl",
            wsa_ioctl_detour,
            FnWsa_ioctl,
            FN_WSA_IOCTL
        )?;

        // Incoming connection hooks (if incoming mode is not Off)
        if network_config.requires_incoming_hooks() {
            tracing::info!("Enabling incoming connection hooks");

            apply_hook!(
                guard,
                "ws2_32",
                "bind",
                bind_detour,
                FnBind,
                FN_BIND
            )?;

            apply_hook!(
                guard,
                "ws2_32",
                "listen",
                listen_detour,
                FnListen,
                FN_LISTEN
            )?;

            apply_hook!(
                guard,
                "ws2_32",
                "accept",
                accept_detour,
                FnAccept,
                FN_ACCEPT
            )?;
        } else {
            tracing::info!("Incoming connection hooks disabled (incoming mode = Off)");
        }

        // Outgoing connection hooks (if outgoing features enabled)
        if network_config.requires_outgoing_hooks() {
            tracing::info!(
                "Enabling outgoing connection hooks (TCP: {}, UDP: {})",
                network_config.requires_tcp_hooks(),
                network_config.requires_udp_hooks()
            );

            apply_hook!(
                guard,
                "ws2_32",
                "connect",
                connect_detour,
                FnConnect,
                FN_CONNECT
            )?;

            apply_hook!(
                guard,
                "ws2_32",
                "WSAConnect",
                wsa_connect_detour,
                FnWsa_connect,
                FN_WSA_CONNECT
            )?;
        } else {
            tracing::info!("Outgoing connection hooks disabled (no outgoing features enabled)");
        }

        if network_config.requires_udp_hooks() {
            tracing::info!("Enabling UDP data transfer hooks");

            apply_hook!(
                guard,
                "ws2_32",
                "sendto",
                sendto_detour,
                FnSendto,
                FN_SENDTO
            )?;

            apply_hook!(
                guard,
                "ws2_32",
                "WSASendTo",
                wsa_send_to_detour,
                FnWsa_send_to,
                FN_WSA_SEND_TO
            )?;
        } else {
            tracing::info!("UDP data transfer hooks disabled (UDP outgoing disabled)");
        }
    } else {
        tracing::info!("Socket operation hooks disabled by configuration");
    }

    tracing::info!("Socket hooks initialization completed");
    Ok(())
}
