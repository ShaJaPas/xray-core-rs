use crate::core::config::Config;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};
use tokio_openssl::SslStream;

use crate::session::Session;

use super::SessionProvider;

pub type UDPWrite = Box<dyn Fn(SocketAddr, String) + Send + Sync>;
pub struct UDPForwardSession {
    session: Session,
    status: Status,
    in_write: UDPWrite,
    out_socket: Option<SslStream<TcpStream>>,
    gc_timer: tokio::time::Sleep,
}
enum Status {
    Connect,
    Forward,
    Forwarding,
    Destroy,
}

impl UDPForwardSession {
    pub fn new(
        config: Config,
        udp_socket: UdpSocket,
        udp_recv_endpoint: SocketAddr,
        in_write: UDPWrite,
    ) -> Self {
        unimplemented!()
    }

    pub fn process(socket_addr: &SocketAddr, data: &[u8]) -> bool {
        unimplemented!()
    }
}

#[async_trait]
impl SessionProvider for UDPForwardSession {
    async fn accept_socket(&self) -> &TcpStream {
        todo!()
    }

    async fn start(&mut self) {
        todo!()
    }
}
