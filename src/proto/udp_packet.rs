use core::str;
use std::{net::SocketAddr, str::FromStr};

use super::BytesForm;

#[derive(Debug, PartialEq, Eq)]
struct UdpPacket {
    address: SocketAddr,
    payload: Vec<u8>,
}

impl BytesForm for UdpPacket {
    type Result = Self;

    fn from_bytes(data: &[u8]) -> Option<UdpPacket> {
        // Validate minimum packet length
        if data.len() < 9 {
            return None;
        }

        // Parse address
        let address_len = data[0] as usize + 1;
        let address = SocketAddr::from_str(str::from_utf8(&data[1..address_len]).unwrap()).unwrap();

        // Parse length
        let length = u16::from_be_bytes([data[address_len], data[address_len + 1]]);

        // Validate CRLF sequence
        if data[address_len + 2..address_len + 4] != [0x0D, 0x0A] {
            return None;
        }
        let payload_start = address_len + 4;
        let payload_end = payload_start + length as usize;
        if payload_end > data.len() {
            return None;
        }
        let payload = data[payload_start..payload_end].to_vec();
        Some(Self { address, payload })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let addr = self.address.to_string().as_bytes().to_vec();
        let mut bytes = Vec::with_capacity(u16::MAX as usize);
        bytes.extend_from_slice(&[addr.len() as u8]);
        bytes.extend_from_slice(&addr);
        bytes.extend_from_slice(&((self.payload.len() as u16).to_be_bytes()));
        bytes.extend_from_slice(&[0x0D, 0x0A]); // CRLF
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::proto::BytesForm;

    use super::UdpPacket;

    #[test]
    fn test_udp_packet() {
        let packet = UdpPacket {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            payload: Vec::from(b"hello"),
        };
        let bytes = packet.to_bytes();
        assert_eq!(UdpPacket::from_bytes(&bytes).unwrap(), packet);
    }
}
