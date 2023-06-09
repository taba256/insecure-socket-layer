use crate::msg::codec::*;

pub enum HashAlgo {
    Md5,
    Sha,
}
impl From<CipherSuite> for HashAlgo {
    fn from(cs: CipherSuite) -> Self {
        match cs {
            CipherSuite::RsaWithRc4_128Md5 => Self::Md5,
            CipherSuite::RsaWithRc4_128Sha => Self::Sha,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    RsaWithRc4_128Md5 = 0x0004,
    RsaWithRc4_128Sha = 0x0005,
}
impl Codec for CipherSuite {
    const SIZE_OF_SELF: Option<std::num::NonZeroUsize> =
        std::num::NonZeroUsize::new(std::mem::size_of::<u16>());
    fn encode(&self, output: &mut Vec<u8>) {
        (*self as u16).encode(output)
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        use CipherSuite::*;
        match u16::decode(input)? {
            0x0004 => Ok(RsaWithRc4_128Md5),
            0x0005 => Ok(RsaWithRc4_128Sha),
            _ => Err(DecodeError::InvalidData),
        }
    }
}

pub fn master_from_pre_master(
    pre_master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Vec<u8> {
    use md5::Digest;
    //use sha1::Digest;
    let mut master_secret = Vec::with_capacity(16 * 3);
    for i in 1..=3 {
        let mut hasher = sha1::Sha1::new();
        for _ in 0..i {
            hasher.update([b'A' + i - 1]);
        }
        hasher.update(pre_master_secret);
        hasher.update(client_random);
        hasher.update(server_random);
        let sha: [u8; 20] = hasher.finalize().into();
        let mut hasher = md5::Md5::new();
        hasher.update(pre_master_secret);
        hasher.update(sha);
        let md5: [u8; 16] = hasher.finalize().into();
        master_secret.extend(md5);
    }
    master_secret
}

pub struct Keys {
    pub client_write_mac: Hmac,
    pub server_write_mac: Hmac,
    pub client_write_key: rc4::Rc4<rc4::consts::U16>,
    pub server_write_key: rc4::Rc4<rc4::consts::U16>,
}
impl Keys {
    pub fn new(
        algo: HashAlgo,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Self {
        use md5::Digest;
        //use sha1::Digest;
        let mut key_block = Vec::with_capacity(16 * 5);
        for i in 1.. {
            let mut hasher = sha1::Sha1::new();
            for _ in 0..i {
                hasher.update([b'A' + i - 1]);
            }
            hasher.update(master_secret);
            hasher.update(server_random);
            hasher.update(client_random);
            let sha: [u8; 20] = hasher.finalize().into();
            let mut hasher = md5::Md5::new();
            hasher.update(master_secret);
            hasher.update(sha);
            let md5: [u8; 16] = hasher.finalize().into();
            key_block.extend(md5);
            if key_block.len() >= 20 + 20 + 16 + 16 {
                break;
            }
        }
        let client_write_mac = match algo {
            HashAlgo::Md5 => Hmac::Md5(
                key_block
                    .drain(..16)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                0,
            ),
            HashAlgo::Sha => Hmac::Sha(
                key_block
                    .drain(..20)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                0,
            ),
        };
        let server_write_mac = match algo {
            HashAlgo::Md5 => Hmac::Md5(
                key_block
                    .drain(..16)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                0,
            ),
            HashAlgo::Sha => Hmac::Sha(
                key_block
                    .drain(..20)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                0,
            ),
        };
        use rc4::KeyInit;
        let client_write_key = rc4::Rc4::new(key_block[..16].try_into().unwrap());
        let server_write_key = rc4::Rc4::new(key_block[16..32].try_into().unwrap());

        Self {
            client_write_mac,
            server_write_mac,
            client_write_key,
            server_write_key,
        }
    }
}
pub enum Hmac {
    Md5([u8; 16], u64),
    Sha([u8; 20], u64),
}
impl Hmac {
    pub fn get_auth_code(&mut self, content_type: u8, message: &[u8]) -> Vec<u8> {
        use md5::Digest;
        match self {
            Self::Md5(key, seq) => {
                let mut hasher = md5::Md5::new();
                hasher.update(&key);
                hasher.update([0x36; 48]);
                hasher.update(seq.to_be_bytes());
                hasher.update([content_type]);
                hasher.update((message.len() as u16).to_be_bytes());
                hasher.update(message);
                let md5_hash: [u8; 16] = hasher.finalize().into();
                let mut hasher = md5::Md5::new();
                hasher.update(key);
                hasher.update([0x5c; 48]);
                hasher.update(md5_hash);
                *seq += 1;
                hasher.finalize().to_vec()
            }
            Self::Sha(key, seq) => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(&key);
                hasher.update([0x36; 40]);
                hasher.update(seq.to_be_bytes());
                hasher.update([content_type]);
                hasher.update((message.len() as u16).to_be_bytes());
                hasher.update(message);
                let sha_hash: [u8; 20] = hasher.finalize().into();
                let mut hasher = sha1::Sha1::new();
                hasher.update(key);
                hasher.update([0x5c; 40]);
                hasher.update(sha_hash);
                *seq += 1;
                hasher.finalize().to_vec()
            }
        }
    }
    pub fn get_hash_len(&self) -> usize {
        match self {
            Self::Md5(..) => 16,
            Self::Sha(..) => 20,
        }
    }
}
