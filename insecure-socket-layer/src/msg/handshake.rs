use super::codec::*;
use crate::{cipher::*, types::*};
use rand::Rng;

pub enum Handshake {
    HelloRequest,
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    //ServerKeyExchange,
    //CertificateRequest,
    ServerHelloDone,
    //CertificateVerify,
    ClientKeyExchange(Vec<u8>),
    Finished(Finished),
}
impl Codec for Handshake {
    fn encode(&self, output: &mut Vec<u8>) {
        use Handshake::*;
        let mut msg_body = Vec::<u8>::new();
        let msg_type = match self {
            HelloRequest => 0,
            ClientHello(ch) => {
                ch.encode(&mut msg_body);
                1
            }
            ServerHello(sh) => {
                sh.encode(&mut msg_body);
                2
            }
            Certificate(cert) => {
                cert.encode(&mut msg_body);
                11
            }
            //ServerKeyExchange => 12,
            //CertificateRequest => 13,
            ServerHelloDone => 14,
            //CertificateVerify => 15,
            ClientKeyExchange(v) => {
                msg_body.extend(v);
                16
            }
            Finished(f) => {
                f.encode(&mut msg_body);
                20
            }
        };
        output.push(msg_type);
        encode_slice::<u8, 3>(output, &msg_body);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        let msg_type = u8::decode(input)?;
        let msg_length = u24::decode(input)?.0 as usize;
        let msg_body = &mut input.slice(msg_length)?;
        match msg_type {
            0 if msg_body.is_eof() => Ok(Self::HelloRequest),
            1 => Ok(Self::ClientHello(ClientHello::decode(msg_body)?)),
            2 => Ok(Self::ServerHello(ServerHello::decode(msg_body)?)),
            11 => Ok(Self::Certificate(Certificate::decode(msg_body)?)),
            14 if msg_body.is_eof() => Ok(Self::ServerHelloDone),
            16 => Ok(Self::ClientKeyExchange(msg_body.take(msg_length)?.to_vec())),
            20 => Ok(Self::Finished(Finished::decode(msg_body)?)),
            _ => Err(DecodeError::InvalidData),
        }
    }
}

pub struct ClientHello {
    // 先頭4バイトはunixtimeであることに注意
    pub random_bytes: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: Vec<CipherSuite>,
}
impl ClientHello {
    pub fn new(cipher_suite: &[CipherSuite]) -> Self {
        let mut rng = rand::thread_rng();
        let mut random_bytes = [0; 32];
        random_bytes[..4].clone_from_slice(&(chrono::Utc::now().timestamp() as u32).to_be_bytes());
        rng.fill(&mut random_bytes[4..]);
        let session_id = vec![];
        let cipher_suite = cipher_suite.to_vec();
        Self {
            random_bytes,
            session_id,
            cipher_suite,
        }
    }
}
impl Codec for ClientHello {
    fn encode(&self, output: &mut Vec<u8>) {
        ProtocolVersion::Ssl30.encode(output);
        output.extend(&self.random_bytes);
        encode_slice::<u8, 1>(output, &self.session_id);
        encode_slice::<CipherSuite, 2>(output, &self.cipher_suite);
        // compression method = null
        encode_slice::<u8, 1>(output, &[0]);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        let protocol = ProtocolVersion::decode(input)?;
        let random_bytes: [u8; 32] = input
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::InvalidData)?;
        let session_id = decode_vec::<u8, 1>(input)?;
        let cipher_suite = decode_vec::<u16, 2>(input)?
            .into_iter()
            .filter_map(|r| {
                if r == CipherSuite::RsaWithRc4_128Md5 as u16 {
                    Some(CipherSuite::RsaWithRc4_128Md5)
                } else if r == CipherSuite::RsaWithRc4_128Sha as u16 {
                    Some(CipherSuite::RsaWithRc4_128Sha)
                } else {
                    None
                }
            })
            .collect::<Vec<CipherSuite>>();
        let _compression_method = decode_vec::<u8, 1>(input)?;

        if protocol != ProtocolVersion::Ssl30 {
            //return Err(DecodeError::InvalidData);
        }
        Ok(ClientHello {
            random_bytes,
            session_id,
            cipher_suite,
        })
    }
}

pub struct ServerHello {
    // 先頭4バイトはunixtimeであることに注意
    pub random_bytes: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: CipherSuite,
}
impl ServerHello {
    pub fn new(session_id: &[u8], cipher_suite: CipherSuite) -> Self {
        let mut rng = rand::thread_rng();
        let mut random_bytes = [0; 32];
        random_bytes[..4].clone_from_slice(&(chrono::Utc::now().timestamp() as u32).to_be_bytes());
        rng.fill(&mut random_bytes[4..]);
        let session_id = if session_id.is_empty() {
            let mut session_id = vec![0; 32];
            rng.fill(&mut session_id[..]);
            session_id
        } else {
            session_id[..32].to_vec()
        };
        Self {
            random_bytes,
            session_id,
            cipher_suite,
        }
    }
}
impl Codec for ServerHello {
    fn encode(&self, output: &mut Vec<u8>) {
        ProtocolVersion::Ssl30.encode(output);
        output.extend(&self.random_bytes);
        encode_slice::<u8, 1>(output, &self.session_id);
        self.cipher_suite.encode(output);
        // compression method = null
        output.push(0);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        let protocol = ProtocolVersion::decode(input)?;
        let random_bytes: [u8; 32] = input
            .take(32)?
            .try_into()
            .map_err(|_| DecodeError::InvalidData)?;
        let session_id = decode_vec::<u8, 1>(input)?;
        let cipher_suite = CipherSuite::decode(input)?;
        let _compression_method = u8::decode(input)?;

        if protocol != ProtocolVersion::Ssl30 {
            return Err(DecodeError::InvalidData);
        }
        Ok(ServerHello {
            random_bytes,
            session_id,
            cipher_suite,
        })
    }
}

pub struct Certificate {
    pub certs: Vec<Vec<u8>>,
}
impl Certificate {
    pub fn new(certs: Vec<Vec<u8>>) -> Self {
        Self { certs }
    }
}
impl Codec for Certificate {
    fn encode(&self, output: &mut Vec<u8>) {
        let sum_of_len = u24(self.certs.iter().map(|cert| cert.len() + 3).sum::<usize>() as u32);
        sum_of_len.encode(output);
        self.certs.iter().for_each(|cert| {
            let len = u24(cert.len() as u32);
            len.encode(output);
            output.extend(cert);
        });
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        let mut certs = vec![];
        let certs_length = u24::decode(input)?.0 as usize;
        let input = &mut input.slice(certs_length)?;
        while !input.is_eof() {
            let cert = decode_vec::<u8, 3>(input)?;
            certs.push(cert);
        }
        Ok(Self { certs })
    }
}

pub struct Finished {
    pub md5_hash: [u8; 16],
    pub sha_hash: [u8; 20],
}
impl Finished {
    pub fn new(master_secret: &[u8], is_client: bool, handshake_messages: &[u8]) -> Self {
        use md5::Digest;
        //use sha1::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(handshake_messages);
        hasher.update(
            (if is_client {
                0x434C4E54u32
            } else {
                0x53525652u32
            })
            .to_be_bytes(),
        );
        hasher.update(master_secret);
        hasher.update([0x36; 48]);
        let md5_hash: [u8; 16] = hasher.finalize().into();
        let mut hasher = md5::Md5::new();
        hasher.update(master_secret);
        hasher.update([0x5c; 48]);
        hasher.update(md5_hash);
        let md5_hash: [u8; 16] = hasher.finalize().into();

        let mut hasher = sha1::Sha1::new();
        hasher.update(handshake_messages);
        hasher.update(
            (if is_client {
                0x434C4E54u32
            } else {
                0x53525652u32
            })
            .to_be_bytes(),
        );
        hasher.update(master_secret);
        hasher.update([0x36; 40]);
        let sha_hash: [u8; 20] = hasher.finalize().into();
        let mut hasher = sha1::Sha1::new();
        hasher.update(master_secret);
        hasher.update([0x5c; 40]);
        hasher.update(sha_hash);
        let sha_hash: [u8; 20] = hasher.finalize().into();

        Self { md5_hash, sha_hash }
    }
}
impl Codec for Finished {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend(&self.md5_hash);
        output.extend(&self.sha_hash);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        let md5_hash = input
            .take(16)?
            .try_into()
            .map_err(|_| DecodeError::InvalidData)?;
        let sha_hash = input
            .take(20)?
            .try_into()
            .map_err(|_| DecodeError::InvalidData)?;
        Ok(Self { md5_hash, sha_hash })
    }
}
