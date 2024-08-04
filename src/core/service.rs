use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    sync::Arc,
};

use openssl::{
    dh::Dh,
    ssl::{
        select_next_proto, AlpnError, Ssl, SslContext, SslFiletype, SslMethod, SslOptions,
        SslSessionCacheMode, SslVerifyMode,
    }
};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio_openssl::SslStream;
use tracing::{debug, error, warn};

use crate::{
    core::{authentificator::Authenticator, config::Config},
    session::{forward_session::UDPForwardSession, server_session::ServerSession, SessionProvider},
};

use super::config::RunType;

pub struct Service {
    config: Arc<Config>,
    tcp_listener: TcpListener,
    udp_socket: Option<UdpSocket>,
    ssl_acceptor: Option<SslStream<TcpStream>>,
    auth: Authenticator,
    plain_http_response: Option<String>,
    udp_sessions: Vec<Arc<UDPForwardSession>>,
    udp_recv_endpoint: Option<SocketAddr>,
    ssl_ctx: SslContext,
}

impl Service {
    pub async fn new_from_config(mut config: Arc<Config>) -> Self {
        if config.run_type == RunType::NAT {
            unimplemented!("NAT is not supported");
        }
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.set_reuseport(config.tcp_config.reuse_port).unwrap();
        socket.bind(config.local_addr).unwrap();
        let udp_socket = if config.run_type == RunType::Forward {
            Some(UdpSocket::bind(config.local_addr).await.unwrap())
        } else {
            None
        };
        //TODO: INITIALIZE TRACING
        tracing_subscriber::fmt()
            .with_max_level(config.log_level)
            .init();
        let mut ssl_context = SslContext::builder(SslMethod::tls_server()).unwrap();
        ssl_context
            .set_options(SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::SINGLE_DH_USE);
        //TODO: curves
        let mut plain_http_response = None;
        if config.run_type == RunType::Server {
            if config.ssl_config.prefer_server_cipher {
                ssl_context
                    .set_options(ssl_context.options() | SslOptions::CIPHER_SERVER_PREFERENCE);
                ssl_context
                    .set_certificate_chain_file(&config.ssl_config.cert)
                    .unwrap();
                // TODO: password callback
                ssl_context
                    .set_private_key_file(&config.ssl_config.key, SslFiletype::PEM)
                    .unwrap();
                // ALPN callback
                if !config.ssl_config.alpn.is_empty() {
                    let config = config.clone();
                    ssl_context.set_alpn_select_callback(move |_, client| {
                        select_next_proto(config.ssl_config.alpn.as_bytes(), client)
                            .ok_or(AlpnError::NOACK)
                    });
                }

                if config.ssl_config.reuse_session {
                    // SSL_CTX_set_timeout missing?
                    if !config.ssl_config.session_ticket {
                        ssl_context.set_options(ssl_context.options() | SslOptions::NO_TICKET);
                    }
                } else {
                    ssl_context.set_session_cache_mode(SslSessionCacheMode::OFF);
                    ssl_context.set_options(ssl_context.options() | SslOptions::NO_TICKET);
                }
                if config.ssl_config.plain_http_response.is_empty() {
                    let mut file = File::open(&config.ssl_config.plain_http_response).unwrap();
                    let mut response = String::new();
                    file.read_to_string(&mut response).unwrap();
                    plain_http_response = Some(response);
                }
                let ssl_dh = Dh::get_2048_256().unwrap();
                ssl_context.set_tmp_dh(&ssl_dh).unwrap();
            }
        } else {
            if config.ssl_config.sni.is_empty() {
                Arc::get_mut(&mut config).unwrap().ssl_config.sni = config.remote_addr.to_string();
            }
            if config.ssl_config.verify {
                ssl_context.set_verify(SslVerifyMode::PEER);
                if config.ssl_config.cert.is_empty() {
                    ssl_context.set_default_verify_paths().unwrap();
                } else {
                    ssl_context.set_ca_file(&config.ssl_config.cert).unwrap();
                }
                if config.ssl_config.verify_hostname {
                    unimplemented!()
                    //ssl_context.set_verify_callback(SslVerifyMode::PEER, verify)
                }
                //X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
                //X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
                //SSL_CTX_set1_param(native_context, param);
                //X509_VERIFY_PARAM_free(param);
            } else {
                ssl_context.set_verify(SslVerifyMode::NONE);
            }

            if !config.ssl_config.alpn.is_empty() {
                ssl_context
                    .set_alpn_protos(config.ssl_config.alpn.as_bytes())
                    .unwrap();
            }
            if config.ssl_config.reuse_session {
                ssl_context.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                //SSLSession::set_callback(native_context);
                if !config.ssl_config.session_ticket {
                    ssl_context.set_options(ssl_context.options() | SslOptions::NO_TICKET);
                }
            } else {
                ssl_context.set_options(ssl_context.options() | SslOptions::NO_TICKET);
            }
        }

        if !config.ssl_config.cipher.is_empty() {
            ssl_context
                .set_cipher_list(config.ssl_config.cipher.as_str())
                .unwrap();
        }
        if !config.ssl_config.cipher_tls13.is_empty() {
            ssl_context
                .set_ciphersuites(config.ssl_config.cipher_tls13.as_str())
                .unwrap();
        }

        socket.set_nodelay(config.tcp_config.no_delay).unwrap();
        socket.set_keepalive(config.tcp_config.keep_alive).unwrap();

        let tcp_listener = socket.listen(1024).unwrap();
        Self {
            config,
            tcp_listener,
            udp_socket,
            ssl_acceptor: None,
            auth: Authenticator,
            plain_http_response,
            udp_sessions: Vec::new(),
            udp_recv_endpoint: None,
            ssl_ctx: ssl_context.build(),
        }
    }

    pub async fn run(&'static self) {
        let mut tasks = vec![tokio::spawn(self.accept())];
        if self.config.run_type == RunType::Forward {
            tasks.push(tokio::spawn(self.udp_read()));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }

    pub fn relaod_certs(&mut self) {
        if self.config.run_type == RunType::Server {
            warn!("reloading certificate and private key. . . ");
            /*self.ssl_ctx
                .set_certificate_chain_file(&self.config.ssl_config.cert)
                .unwrap();
            self.ssl_ctx
                .set_private_key_file(&self.config.ssl_config.key, SslFiletype::PEM)
                .unwrap();*/
            unimplemented!()
        }
        {
            error!("cannot reload certificate and private key: wrong run_type");
        }
    }

    async fn udp_read(&self) {
        let socket = self.udp_socket.as_ref().unwrap();
        let mut buf = Vec::with_capacity(u16::MAX as usize);
        loop {
            let (size, addr) = socket.recv_from(&mut buf).await.unwrap();
            debug!("Received datagram from {addr} with size {size}");
        }
    }

    async fn accept<'a>(&'a self) {
        loop {
            let (stream, addr) = self.tcp_listener.accept().await.unwrap();
            debug!("Socket with addr {addr} was accepted");
            let in_socket = SslStream::new(Ssl::new(&self.ssl_ctx).unwrap(), stream).unwrap();
            let mut session: Box<dyn SessionProvider> = match self.config.run_type {
                RunType::Server => Box::new(ServerSession::new_from_config(
                    self.config.clone(),
                    in_socket,
                    //self.out_socket,
                    self.auth.clone(),
                    self.plain_http_response.clone(),
                )),
                RunType::Client => todo!(),
                RunType::Forward => todo!(),
                RunType::NAT => todo!(),
            };
            tokio::spawn(async move { session.start().await });
        }
    }
}
