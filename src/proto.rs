mod trojan_request;
mod udp_packet;

trait BytesForm {
    type Result;
    fn from_bytes(data: &[u8]) -> Option<Self::Result>;
    fn to_bytes(&self) -> Vec<u8>;
}
