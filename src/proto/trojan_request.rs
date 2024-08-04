use std::net::SocketAddr;

use super::BytesForm;

struct TrojanRequest {
    password: String,
    cmd: Command,
    address: SocketAddr,
    payload: Vec<u8>,
    tcp: bool,
}

#[repr(u8)]
enum Command {
    Connect,
    UdpAssociate,
}

impl BytesForm for TrojanRequest {
    type Result = Self;

    fn from_bytes(data: &[u8]) -> Option<Self::Result> {
        todo!()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::from(self.password.as_bytes());
        vec.extend_from_slice(&[0x0D, 0x0A]);
        vec.extend_from_slice(&[self.tcp as u8]);
        vec.extend_from_slice(&[0x03]);
        vec.extend_from_slice(self.address.to_string().as_bytes());
        vec
    }
}
