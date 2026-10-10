use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;

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

    let mut buf = body.as_slice();
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
