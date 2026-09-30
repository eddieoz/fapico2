use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::ccid;

pub const DEFAULT_CCID_PORT: u16 = 35963;
pub const DEFAULT_HID_PORT: u16 = 35962;

pub struct EmulationTransport {
    ccid_sock: Option<TcpStream>,
    hid_listener: Option<TcpListener>,
    hid_client: Option<TcpStream>,
    ccid_buf: Vec<u8>,
    hid_buf: Vec<u8>,
}

impl EmulationTransport {
    pub fn new(ccid_addr: std::net::SocketAddr, hid_port: u16) -> Result<Self, std::io::Error> {
        let ccid_sock = match TcpStream::connect(ccid_addr) {
            Ok(sock) => {
                // A short timeout keeps the single-threaded loop responsive
                // to HID traffic while a CCID relay is connected but idle.
                sock.set_read_timeout(Some(Duration::from_millis(5)))?;
                Some(sock)
            }
            Err(_) => {
                eprintln!("ccid relay not available, running in FIDO-only mode");
                None
            }
        };

        let hid_listener = TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::UNSPECIFIED,
            hid_port,
        )))?;
        hid_listener.set_nonblocking(true)?;

        eprintln!(
            "emulation: ccid={}, hid listening on {}",
            if ccid_sock.is_some() {
                "connected"
            } else {
                "FIDO-only"
            },
            hid_port
        );

        Ok(Self {
            ccid_sock,
            hid_listener: Some(hid_listener),
            hid_client: None,
            ccid_buf: Vec::new(),
            hid_buf: Vec::new(),
        })
    }

    pub fn read_ccid(&mut self) -> Option<Vec<u8>> {
        let sock = self.ccid_sock.as_mut()?;
        let mut tmp = [0u8; 1024];
        match sock.read(&mut tmp) {
            Ok(0) => {
                self.ccid_sock = None;
                None
            }
            Ok(n) => {
                self.ccid_buf.extend_from_slice(&tmp[..n]);
                if let Some(body) = ccid::decode(&self.ccid_buf) {
                    let body = body.to_vec();
                    let len = body.len() + 2;
                    self.ccid_buf.drain(..len);
                    Some(body)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn write_ccid(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        let sock = self
            .ccid_sock
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "ccid closed"))?;
        let mut buf = Vec::with_capacity(2 + data.len());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        sock.write_all(&buf)
    }

    /// Try to accept a new HID client connection. Returns `true` if a new
    /// client was accepted (replacing any previous one), `false` otherwise.
    pub fn accept_hid_client(&mut self) -> Result<bool, std::io::Error> {
        if let Some(listener) = &self.hid_listener {
            match listener.accept() {
                Ok((sock, addr)) => {
                    eprintln!("hid client connected: {}", addr);
                    // Short read timeout keeps the main loop cycling so
                    // transaction idle timeouts fire on schedule.
                    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
                    self.hid_client = Some(sock);
                    return Ok(true);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    pub fn read_hid(&mut self) -> Option<Vec<u8>> {
        // First, try to decode from already-accumulated buffer (handles
        // multi-frame messages where continuation packets arrived in a
        // previous read).
        if let Some(body) = ccid::decode(&self.hid_buf) {
            let body = body.to_vec();
            let len = body.len() + 2;
            self.hid_buf.drain(..len);
            return Some(body);
        }

        let sock = self.hid_client.as_mut()?;
        let mut tmp = [0u8; 1024];
        match sock.read(&mut tmp) {
            Ok(0) => {
                self.hid_client = None;
                None
            }
            Ok(n) => {
                self.hid_buf.extend_from_slice(&tmp[..n]);
                if let Some(body) = ccid::decode(&self.hid_buf) {
                    let body = body.to_vec();
                    let len = body.len() + 2;
                    self.hid_buf.drain(..len);
                    Some(body)
                } else {
                    None
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                None
            }
            Err(_) => {
                self.hid_client = None;
                None
            }
        }
    }

    pub fn write_hid(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        let sock = self
            .hid_client
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "hid closed"))?;
        let mut buf = Vec::with_capacity(2 + data.len());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        sock.write_all(&buf)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn ccid_ports_match_c_default() {
        assert_eq!(
            DEFAULT_CCID_PORT, 35963,
            "CCID port must match C emulation.c"
        );
        assert_eq!(
            DEFAULT_HID_PORT, 35962,
            "HID port must be CCID-1 (matches C)"
        );
    }
}
