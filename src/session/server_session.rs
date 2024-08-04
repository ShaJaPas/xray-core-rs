use std::{io::BufReader, pin::Pin, sync::Arc};

use async_trait::async_trait;
use tokio::net::{TcpSocket, TcpStream};
use tokio_openssl::SslStream;

use crate::core::{authentificator::Authenticator, config::Config};

use super::{Session, SessionProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub struct ServerSession {
    session: Session,
    status: Status,
    in_socket: SslStream<TcpStream>,
    //out_socket: TcpSocket,
    //boost::asio::ip::udp::resolver udp_resolver;
    auth: Authenticator,
    auth_pswd: String,
    plain_http_response: Option<String>,
}

impl ServerSession {
    pub fn new_from_config(
        config: Arc<Config>,
        in_socket: SslStream<TcpStream>,
        //out_socket: TcpSocket,
        auth: Authenticator,
        response: Option<String>,
    ) -> Self {
        Self {
            session: Session::new_from_config(config),
            status: Status::Handshake,
            in_socket,
            //out_socket,
            auth,
            auth_pswd: String::new(),
            plain_http_response: response,
        }
    }

    async fn in_read(&mut self) {
        let pinned = Pin::new(&mut self.in_socket);
        //let buf_reader = BufReader::new(pinned);
    }

    async fn out_write(&mut self) {
        let pinned = Pin::new(&mut self.in_socket);
        //let buf_reader = BufReader::new(pinned);
    }

    async fn in_recv(&mut self, bytes: &[u8]) {
        match self.status {
            Status::Handshake => {
                todo!()
            }
            Status::Forward => {
                self.session.sent_len += bytes.len();
            }
            Status::UdpForward => todo!(),
        }
    }
}
enum Status {
    Handshake,
    Forward,
    UdpForward,
}

#[async_trait]
impl SessionProvider for ServerSession {
    async fn accept_socket(&self) -> &TcpStream {
        self.in_socket.get_ref()
    }

    async fn start(&mut self) {
        let socket = self.in_socket.get_ref();
        //let in_addr = socket.peer_addr().unwrap();
        //Pin::new(&mut self.in_socket).accept().await.unwrap();
    }
}
