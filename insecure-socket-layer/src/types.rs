use crate::msg::codec::*;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtocolVersion {
    Ssl30 = 0x0300,
    Tls10 = 0x0301,
}
impl Codec for ProtocolVersion {
    const SIZE_OF_SELF: Option<std::num::NonZeroUsize> =
        std::num::NonZeroUsize::new(std::mem::size_of::<u16>());
    fn encode(&self, output: &mut Vec<u8>) {
        (*self as u16).encode(output)
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        use ProtocolVersion::*;
        match u16::decode(input)? {
            0x0300 => Ok(Ssl30),
            0x0301 => Ok(Tls10),
            _ => Err(DecodeError::InvalidData),
        }
    }
}
