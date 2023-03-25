use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    start_http_server();
    start_https_server();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn handle_http<S>(mut stream: S) -> std::io::Result<()>
where
    S: Read + Write,
{
    let mut buffer = [0; 2048];
    let read_len = stream.read(&mut buffer)?;
    let buffer = &buffer[0..read_len];
    stream.write_all(b"HTTP/1.1 200 OK\r\n")?;
    stream.write_all(format!("Content-length: {read_len}\r\n").as_bytes())?;
    stream.write_all(b"\r\n")?;
    stream.write_all(buffer)?;
    stream.flush()?;
    Ok(())
}

fn start_http_server() {
    std::thread::spawn(move || -> std::io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:80");
        eprintln!("{listener:?}");
        let listener = listener?;
        eprintln!("http server started");
        for stream in listener.incoming() {
            eprintln!("connection accepted");
            handle_http(stream?)?;
        }
        Ok(())
    });
}

fn start_https_server() {
    std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Sync + Send + 'static>> {
            let listener = TcpListener::bind("127.0.0.1:443");
            eprintln!("{listener:?}");
            let listener = listener?;
            eprintln!("https server started");
            let config = insecure_socket_layer::server::ServerConfigBuilder::new()
                .add_cert(include_bytes!("server.der"))
                .set_private_key_pkcs1_pem(include_str!("server.key"))
                .build();
            for stream in listener.incoming() {
                let config = config.clone();
                std::thread::spawn(
                    move || -> Result<(), Box<dyn std::error::Error + Sync + Send + 'static>> {
                        eprintln!("ssl connection accepted");
                        let stream = match insecure_socket_layer::server::ServerStream::new(
                            stream?,
                            config.clone(),
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("ssl stream error: {e:?}");
                                return Err(e.into());
                            }
                        };
                        handle_http(stream)?;
                        Ok(())
                    },
                );
            }
            Ok(())
        },
    );
}
