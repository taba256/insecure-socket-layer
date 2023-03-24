use crate::{
    cipher::*,
    fragment::*,
    msg::{codec::*, handshake::*, *},
    server::config::*,
    types::*,
    Result,
};
use rc4::StreamCipher;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    sync::Arc,
};

pub struct ServerStream<S> {
    stream: S,
    config: Arc<ServerConfig>,
    defrag: RecordDefragContext,
    disabled: bool,
    decrypter: Option<(rc4::Rc4<rc4::consts::U16>, Hmac)>,
    encrypter: Option<(rc4::Rc4<rc4::consts::U16>, Hmac)>,
}
impl<S> ServerStream<S>
where
    S: Read + Write,
{
    pub fn new(stream: S, config: Arc<ServerConfig>) -> Result<Self> {
        let mut s = Self {
            stream,
            config,
            defrag: RecordDefragContext::new(),
            disabled: false,
            decrypter: None,
            encrypter: None,
        };
        s.handshake()?;
        Ok(s)
    }
    pub fn into_inner(self) -> S {
        self.stream
    }
    fn handshake(&mut self) -> Result<()> {
        let mut handshake_messages = Vec::new();
        let Message::Handshake(Handshake::ClientHello(client_hello)) = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ClientHello".into()))};
        let ClientHello {
            random_bytes: client_random,
            session_id,
            cipher_suite,
        } = client_hello;

        let cipher_suite = if cipher_suite.contains(&CipherSuite::RsaWithRc4_128Sha) {
            CipherSuite::RsaWithRc4_128Sha
        } else if cipher_suite.contains(&CipherSuite::RsaWithRc4_128Md5) {
            CipherSuite::RsaWithRc4_128Md5
        } else {
            return Err(crate::error::Error::Handshake(
                "no available cipher suite".into(),
            ));
        };
        let server_hello = ServerHello::new(&session_id, cipher_suite);
        let server_random = server_hello.random_bytes;
        self.write_message(
            Message::Handshake(Handshake::ServerHello(server_hello)),
            Some(&mut handshake_messages),
        )?;

        let certificate = Certificate::new(self.config.certs.clone());
        self.write_message(
            Message::Handshake(Handshake::Certificate(certificate)),
            Some(&mut handshake_messages),
        )?;

        self.write_message(
            Message::Handshake(Handshake::ServerHelloDone),
            Some(&mut handshake_messages),
        )?;

        let Message::Handshake(Handshake::ClientKeyExchange(client_key_exchange)) = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ClientKeyExchange".into()))};
        let mut pre_master_secret = client_key_exchange;
        self.config
            .private_key
            .decrypt(rsa::Pkcs1v15Encrypt, &mut pre_master_secret)
            .expect("RSA decryption failed");

        let master_secret =
            master_from_pre_master(&pre_master_secret, &client_random, &server_random);

        // pre_master_secretには速やかにメモリから消滅していただく。
        drop(pre_master_secret);
        let keys = Keys::new(
            cipher_suite.into(),
            &master_secret,
            &client_random,
            &server_random,
        );

        let Message::ChangeCipherSpec = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ChangeCipherSpec".into()))};
        self.decrypter = Some((keys.client_write_key, keys.client_write_mac));

        let Message::Handshake(Handshake::Finished(client_finished)) = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ClientKeyExchange".into()))};

        self.write_message(Message::ChangeCipherSpec, Some(&mut handshake_messages))?;
        self.encrypter = Some((keys.server_write_key, keys.server_write_mac));

        let server_finished = Finished::new(&master_secret, false, &handshake_messages);
        self.write_message(
            Message::Handshake(Handshake::Finished(server_finished)),
            None,
        )?;

        Ok(())
    }
    fn read_ssl_record_fragment(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut record_header = [0; 5];
        self.stream.read_exact(&mut record_header)?;

        let input = &mut Reader::new(&record_header);
        let content_type = u8::decode(input)?;
        let protocol_version = ProtocolVersion::decode(input)?;
        let fragment_size = u16::decode(input)? as usize;

        let mut fragment = vec![0; fragment_size];
        self.stream.read_exact(&mut fragment)?;

        if let Some((decrypter, hmac)) = &mut self.decrypter {
            decrypter.apply_keystream(&mut fragment);
        }

        Ok((content_type, fragment))
    }
    fn read_next_message(&mut self, mut raw_message: Option<&mut Vec<u8>>) -> Result<Message> {
        loop {
            if let Some(msg) = self.defrag.next_message() {
                if let Message::Alert(level, desc) = msg {
                    if level == AlertLevel::Warn {
                        tracing::warn!("ssl alert: {desc:?}");
                    } else {
                        tracing::error!("ssl alert: {desc:?}");
                    }
                    if desc == AlertDescription::CloseNotify {
                        self.disabled = true;
                    }
                }
                return Ok(msg);
            }
            let (content_type, fragment) = self.read_ssl_record_fragment()?;
            let available_message_num = self.defrag.extend_buffer(content_type, &fragment)?;
            if let Some(ref mut raw_message) = &mut raw_message {
                if content_type == 22 {
                    raw_message.extend(&fragment);
                }
            }
        }
    }
    fn write_message(
        &mut self,
        msg: Message,
        mut raw_message: Option<&mut Vec<u8>>,
    ) -> std::io::Result<()> {
        if self.disabled {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        let content_type = msg.content_type();
        let bytes = msg.encode();
        if let Some(ref mut raw_message) = &mut raw_message {
            raw_message.extend(&bytes);
        }
        for chunk in bytes.chunks(16384) {
            let mut chunk = chunk.to_vec();
            if let Some((encrypter, hmac)) = &mut self.encrypter {
                let mac = hmac.get_auth_code(&chunk);
                chunk.extend(mac);
                encrypter.apply_keystream(&mut chunk);
            }
            let header = &mut Vec::with_capacity(5);
            content_type.encode(header);
            ProtocolVersion::Ssl30.encode(header);
            (chunk.len() as u16).encode(header);
            self.stream.write_all(&header)?;
            self.stream.write_all(&chunk)?;
        }
        self.stream.flush()?;
        Ok(())
    }
}
impl<S> Read for ServerStream<S> {
    fn read(&mut self, _: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        todo!()
    }
}
impl<S> Write for ServerStream<S> {
    fn write(&mut self, _: &[u8]) -> std::result::Result<usize, std::io::Error> {
        todo!()
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        todo!()
    }
}