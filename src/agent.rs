use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
// OpenSSH's AGENT_MAX_LEN; clients are untrusted, so cap what a length prefix can allocate
const MAX_FRAME: usize = 256 * 1024;

pub fn listen(socket: &Path) -> io::Result<UnixListener> {
    let _ = std::fs::remove_file(socket);
    UnixListener::bind(socket)
}

pub fn serve(listener: UnixListener, upstream: String, chosen: Arc<Mutex<Vec<u8>>>) {
    for client in listener.incoming() {
        let upstream = upstream.clone();
        let chosen = chosen.clone();
        match client {
            Ok(client) => {
                thread::spawn(move || {
                    if let Err(e) = proxy(client, &upstream, &chosen) {
                        eprintln!("whoami: client: {e}");
                    }
                });
            }
            Err(e) => eprintln!("whoami: accept: {e}"),
        }
    }
}

// the agent protocol is strict request/reply, so one frame in, one frame out
// DRAFT policy: list only the chosen key, refuse signing with any other, pass everything else through
fn proxy(mut client: UnixStream, upstream: &str, chosen: &Mutex<Vec<u8>>) -> io::Result<()> {
    let mut upstream = UnixStream::connect(upstream)?;
    while let Some(request) = read_frame(&mut client)? {
        let kind = request.first().copied();
        let reply = if kind == Some(SIGN_REQUEST)
            && take_string(&mut &request[1..])? != chosen.lock().unwrap().as_slice()
        {
            vec![FAILURE]
        } else {
            write_frame(&mut upstream, &request)?;
            let reply = read_frame(&mut upstream)?.ok_or(io::ErrorKind::UnexpectedEof)?;
            if kind == Some(REQUEST_IDENTITIES) {
                only_chosen(&reply, &chosen.lock().unwrap())?
            } else {
                reply
            }
        };
        write_frame(&mut client, &reply)?;
    }
    Ok(())
}

fn only_chosen(answer: &[u8], chosen: &[u8]) -> io::Result<Vec<u8>> {
    let identities = parse_identities(answer)?;
    let kept: Vec<_> = identities.iter().filter(|i| i.key_blob == chosen).collect();
    let mut out = vec![IDENTITIES_ANSWER];
    out.extend((kept.len() as u32).to_be_bytes());
    for identity in kept {
        put_string(&mut out, &identity.key_blob);
        put_string(&mut out, identity.comment.as_bytes());
    }
    Ok(out)
}

// None when the peer closed the connection between frames
fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 4];
    match stream.read_exact(&mut len) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        r => r?,
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::other(format!("frame too large: {len}")));
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)
}

#[derive(Debug)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

pub fn list_identities(socket: &str) -> io::Result<Vec<Identity>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(&[0, 0, 0, 1, REQUEST_IDENTITIES])?;

    let mut len = [0; 4];
    stream.read_exact(&mut len)?;
    let mut body = vec![0; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body)?;
    parse_identities(&body)
}

fn parse_identities(body: &[u8]) -> io::Result<Vec<Identity>> {
    let mut buf = body;
    if take(&mut buf, 1)? != [IDENTITIES_ANSWER] {
        return Err(io::Error::other("unexpected agent reply"));
    }
    (0..take_u32(&mut buf)?)
        .map(|_| {
            Ok(Identity {
                key_blob: take_string(&mut buf)?.to_vec(),
                comment: String::from_utf8_lossy(take_string(&mut buf)?).into_owned(),
            })
        })
        .collect()
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    let (head, tail) = buf
        .split_at_checked(n)
        .ok_or(io::ErrorKind::UnexpectedEof)?;
    *buf = tail;
    Ok(head)
}

fn take_u32(buf: &mut &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(take(buf, 4)?.try_into().unwrap()))
}

fn take_string<'a>(buf: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let n = take_u32(buf)? as usize;
    take(buf, n)
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s);
}
