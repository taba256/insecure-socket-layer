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
    application_read_buffer: VecDeque<u8>,
    application_write_buffer: VecDeque<u8>,
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
            application_read_buffer: VecDeque::new(),
            application_write_buffer: VecDeque::new(),
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

        let prev_session = self
            .config
            .sessions
            .read()
            .unwrap()
            .get(&session_id)
            .cloned();
        if let Some((cipher_suite, master_secret)) = prev_session {
            // セッション再開
            let server_hello = ServerHello::new(&session_id, cipher_suite);
            let server_random = server_hello.random_bytes;
            self.write_message(
                Message::Handshake(Handshake::ServerHello(server_hello)),
                Some(&mut handshake_messages),
            )?;
            let keys = Keys::new(
                cipher_suite.into(),
                &master_secret,
                &client_random,
                &server_random,
            );

            self.write_message(Message::ChangeCipherSpec, None)?;
            self.encrypter = Some((keys.server_write_key, keys.server_write_mac));

            let server_finished = Finished::new(&master_secret, false, &handshake_messages);
            self.write_message(
                Message::Handshake(Handshake::Finished(server_finished)),
                None,
            )?;

            let Message::ChangeCipherSpec = self.read_next_message(None)? else {return Err(crate::error::Error::Handshake("ChangeCipherSpec".into()))};
            self.decrypter = Some((keys.client_write_key, keys.client_write_mac));

            let Message::Handshake(Handshake::Finished(_client_finished)) = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ClientKeyExchange".into()))};

            return Ok(());
        }

        // 新規セッション
        let cipher_suite = if cipher_suite.contains(&CipherSuite::RsaWithRc4_128Sha) {
            CipherSuite::RsaWithRc4_128Sha
        } else if cipher_suite.contains(&CipherSuite::RsaWithRc4_128Md5) {
            CipherSuite::RsaWithRc4_128Md5
        } else {
            return Err(crate::error::Error::Handshake(
                "no available cipher suite".into(),
            ));
        };
        let server_hello = ServerHello::new(&[], cipher_suite);
        let server_random = server_hello.random_bytes;
        let session_id = server_hello.session_id.clone();
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
        let pre_master_secret = client_key_exchange;
        let pre_master_secret = self
            .config
            .private_key
            .decrypt(rsa::Pkcs1v15Encrypt, &pre_master_secret)
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

        let Message::ChangeCipherSpec = self.read_next_message(None)? else {return Err(crate::error::Error::Handshake("ChangeCipherSpec".into()))};
        self.decrypter = Some((keys.client_write_key, keys.client_write_mac));

        let Message::Handshake(Handshake::Finished(_client_finished)) = self.read_next_message(Some(&mut handshake_messages))? else {return Err(crate::error::Error::Handshake("ClientKeyExchange".into()))};

        self.write_message(Message::ChangeCipherSpec, None)?;
        self.encrypter = Some((keys.server_write_key, keys.server_write_mac));

        let server_finished = Finished::new(&master_secret, false, &handshake_messages);
        self.write_message(
            Message::Handshake(Handshake::Finished(server_finished)),
            None,
        )?;

        self.config
            .sessions
            .write()
            .unwrap()
            .insert(session_id, (cipher_suite, master_secret));

        Ok(())
    }
    fn read_ssl_record_fragment(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut record_header = [0; 5];
        self.stream.read_exact(&mut record_header)?;

        let input = &mut Reader::new(&record_header);
        let content_type = u8::decode(input)?;
        let _protocol_version = ProtocolVersion::decode(input)?;
        let fragment_size = u16::decode(input)? as usize;

        let mut fragment = vec![0; fragment_size];
        self.stream.read_exact(&mut fragment)?;

        if let Some((decrypter, _)) = &mut self.decrypter {
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
            let fragment = if let Some((_, hmac)) = &mut self.decrypter {
                let message = &fragment[..fragment.len() - hmac.get_hash_len()];
                let mac = &fragment[fragment.len() - hmac.get_hash_len()..];
                assert_eq!(&hmac.get_auth_code(content_type, message), mac);
                message
            } else {
                &fragment
            };
            if let Some(ref mut raw_message) = &mut raw_message {
                if content_type == 22 {
                    raw_message.extend(fragment);
                }
            }
            let _available_message_num = self.defrag.extend_buffer(content_type, fragment)?;
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
                let mac = hmac.get_auth_code(content_type, &chunk);
                chunk.extend(mac);
                encrypter.apply_keystream(&mut chunk);
            }
            let header = &mut Vec::with_capacity(5);
            content_type.encode(header);
            ProtocolVersion::Ssl30.encode(header);
            (chunk.len() as u16).encode(header);
            self.stream.write_all(header)?;
            self.stream.write_all(&chunk)?;
        }
        self.stream.flush()?;
        Ok(())
    }
    fn send_application_data(&mut self) -> Result<usize> {
        if self.application_write_buffer.is_empty() {
            return Ok(0);
        }
        let write_size = std::cmp::min(self.application_write_buffer.len(), 16384);
        let v = self
            .application_write_buffer
            .drain(..write_size)
            .collect::<Vec<u8>>();
        let message = Message::ApplicationData(v);
        self.write_message(message, None)?;
        Ok(write_size)
    }
}
impl<S> Read for ServerStream<S>
where
    S: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        loop {
            if self.disabled {
                // todo 切断された理由によってOkとErrを切り替えたほうがよろしいのでは？
                return Ok(0);
            }
            if !self.application_read_buffer.is_empty() {
                let read_size = std::cmp::min(buf.len(), self.application_read_buffer.len());
                buf.iter_mut()
                    .take(read_size)
                    .for_each(|b| *b = self.application_read_buffer.pop_front().unwrap());
                return Ok(read_size);
            }
            let message = match self.read_next_message(None) {
                Ok(msg) => msg,
                Err(crate::error::Error::Io(e)) => {
                    self.disabled = true;
                    return Err(e);
                }
                Err(e) => {
                    self.disabled = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        e,
                    ));
                }
            };
            if let Message::ApplicationData(data) = message {
                self.application_read_buffer.extend(data);
            }
        }
    }
}
impl<S> Write for ServerStream<S>
where
    S: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.application_write_buffer.extend(buf);
        while self.application_write_buffer.len() >= 16384 {
            match self.send_application_data() {
                Ok(..) => {}
                Err(crate::error::Error::Io(e)) => {
                    self.disabled = true;
                    return Err(e);
                }
                Err(e) => {
                    self.disabled = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        e,
                    ));
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        while !self.application_write_buffer.is_empty() {
            match self.send_application_data() {
                Ok(_) => (),
                Err(crate::error::Error::Io(e)) => {
                    self.disabled = true;
                    return Err(e);
                }
                Err(e) => {
                    self.disabled = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        e,
                    ));
                }
            };
        }
        Ok(())
    }
}
