pub(crate) mod codec;
pub(crate) mod handshake;

use codec::*;
use handshake::Handshake;

pub enum Message {
    ChangeCipherSpec,
    Alert(AlertLevel, AlertDescription),
    Handshake(Handshake),
    ApplicationData(Vec<u8>),
}
impl Message {
    pub fn content_type(&self) -> u8 {
        use Message::*;
        match self {
            ChangeCipherSpec => 20,
            Alert(_, _) => 21,
            Handshake(_) => 22,
            ApplicationData(_) => 23,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        use Message::*;
        let mut body = vec![];
        match self {
            ChangeCipherSpec => {
                body.push(1);
            }
            Alert(level, desc) => {
                level.encode(&mut body);
                desc.encode(&mut body);
            }
            Handshake(hs) => {
                hs.encode(&mut body);
            }
            ApplicationData(d) => {
                body.extend(d);
            }
        }
        body
    }
    pub fn decode(content_type: u8, input: &mut Reader) -> Result<Self> {
        match content_type {
            20 => {
                // ChangeCipherSpec
                input.take_byte()?;
                Ok(Message::ChangeCipherSpec)
            }
            21 => {
                // Alert(AlertLevel, AlertDescription)
                let level = AlertLevel::decode(input)?;
                let desc = AlertDescription::decode(input)?;
                Ok(Message::Alert(level, desc))
            }
            22 => {
                // Handshake(Handshake)
                let handshake = Handshake::decode(input)?;
                Ok(Message::Handshake(handshake))
            }
            23 => {
                // ApplicationData(Vec<u8>)
                Ok(Message::ApplicationData(input.remain()?.to_vec()))
            }
            _ => Err(DecodeError::InvalidData),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warn = 1,
    Fatal = 2,
    Unknown = 255,
}
impl Codec for AlertLevel {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self as u8);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        match input.take_byte()? {
            1 => Ok(Self::Warn),
            2 => Ok(Self::Fatal),
            _ => Ok(Self::Unknown),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = (0),
    UnexpectedMessage = (10),
    BadRecordMac = (20),
    DecompressionFailure = (30),
    HandshakeFailure = (40),
    NoCertificate = (41),
    BadCertificate = (42),
    UnsupportedCertificate = (43),
    CertificateRevoked = (44),
    CertificateExpired = (45),
    CertificateUnknown = (46),
    IllegalParameter = (47),
    Unknown = 255,
}
impl Codec for AlertDescription {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self as u8);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        match input.take_byte()? {
            0 => Ok(Self::CloseNotify),
            10 => Ok(Self::UnexpectedMessage),
            20 => Ok(Self::BadRecordMac),
            30 => Ok(Self::DecompressionFailure),
            40 => Ok(Self::HandshakeFailure),
            41 => Ok(Self::NoCertificate),
            42 => Ok(Self::BadCertificate),
            43 => Ok(Self::UnsupportedCertificate),
            44 => Ok(Self::CertificateRevoked),
            45 => Ok(Self::CertificateExpired),
            46 => Ok(Self::CertificateUnknown),
            47 => Ok(Self::IllegalParameter),
            _ => Ok(Self::Unknown),
        }
    }
}
