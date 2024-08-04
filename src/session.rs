use crate::core::config::Config;
use std::{net::SocketAddr, sync::Arc, time::Instant};

use async_trait::async_trait;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    time::Sleep,
};

pub mod forward_session;
pub mod server_session;

const MAX_LENGTH: usize = 8192;
const SSL_SHUTDOWN_TIMEOUT: u64 = 30;

struct Session {
    config: Config,
    //uint8_t in_read_buf[MAX_LENGTH]{};
    //uint8_t out_read_buf[MAX_LENGTH]{};
    //uint8_t udp_read_buf[MAX_LENGTH]{};
    recv_len: usize,
    sent_len: usize,
    start_time: Instant,
    out_write_buf: Vec<u8>,
    udp_data_buf: Vec<u8>,
    //boost::asio::ip::tcp::resolver resolver;
    in_endpoint: SocketAddr,
    udp_socket: UdpSocket,
    udp_recv_endpoint: SocketAddr,
    ssl_shutdown_timer: Sleep,
}

impl Session {
    pub fn new_from_config(config: Arc<Config>) -> Self {
        unimplemented!()
    }
}

#[async_trait]
pub trait SessionProvider: Send {
    async fn accept_socket(&self) -> &TcpStream;
    async fn start(&mut self);
}
