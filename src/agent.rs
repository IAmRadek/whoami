use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
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

// a key list waiting for the user; the UI answers on `reply` with the chosen identity, or None on cancel
pub struct Pick {
    pub identities: Vec<Identity>,
    // the client's current directory; for `git push` the client is `ssh`, started in git's directory
    pub cwd: Option<PathBuf>,
    // the repository in the client's command line, such as `org/repo.git`
    pub repo: Option<String>,
    // the host in an ssh client's destination, such as `github.com`, or the alias from ~/.ssh/config
    pub host: Option<String>,
    pub reply: mpsc::Sender<Option<Identity>>,
}

// ssh's options that take a value, from its usage text
const SSH_OPTIONS_WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

// the destination is ssh's first argument after the options: `[user@]host` or
// `ssh://[user@]host[:port][/path]`; the user and port are dropped
fn host(args: &[String]) -> Option<String> {
    let (program, args) = args.split_first()?;
    (Path::new(program).file_name()? == "ssh").then_some(())?;
    let mut args = args.iter();
    let destination = loop {
        let arg = args.next()?;
        if arg == "--" {
            break args.next()?;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            break arg;
        };
        // flags combine as in `-xp22` or `-xp 22`; a flag with a value takes the rest or the next argument
        if let Some(i) = flags.find(|c| SSH_OPTIONS_WITH_VALUE.contains(c))
            && i + 1 == flags.len()
        {
            args.next()?;
        }
    };
    let destination = destination.strip_prefix("ssh://").unwrap_or(destination);
    let destination = destination.split('/').next()?;
    let host = destination
        .rsplit_once('@')
        .map_or(destination, |(_, host)| host);
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

// git gives ssh the remote command as one argument, such as `git-upload-pack 'org/repo.git'`;
// an ssh:// URL gives the path with a leading slash
fn repository(args: &[String]) -> Option<String> {
    args.iter().find_map(|arg| {
        let (command, path) = arg.split_once(' ')?;
        command.starts_with("git-").then_some(())?;
        Some(path.trim_matches('\'').trim_start_matches('/').to_string())
    })
}

// DRAFT: what the proxy asks of the UI
pub enum Request {
    Pick(Pick),
    Unavailable,
}

pub fn serve(listener: UnixListener, upstream: String, picks: mpsc::Sender<Request>) {
    for client in listener.incoming() {
        let upstream = upstream.clone();
        let picks = picks.clone();
        match client {
            Ok(client) => {
                thread::spawn(move || {
                    if let Err(e) = proxy(client, &upstream, &picks) {
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
fn proxy(mut client: UnixStream, upstream: &str, picks: &mpsc::Sender<Request>) -> io::Result<()> {
    let mut upstream = match UnixStream::connect(upstream) {
        Ok(stream) => stream,
        Err(e) => {
            let _ = picks.send(Request::Unavailable);
            return Err(e);
        }
    };
    let pid = crate::macos::peer_pid(&client);
    let cwd = pid.and_then(crate::macos::cwd);
    let args = pid.and_then(crate::macos::args);
    let repo = args.as_deref().and_then(repository);
    let host = args.as_deref().and_then(host);
    eprintln!(
        "whoami: client pid {pid:?} in {cwd:?} for host {host:?} and repository {repo:?}, args {args:?}"
    );
    let mut chosen: Option<Vec<u8>> = None;
    while let Some(request) = read_frame(&mut client)? {
        let kind = request.first().copied();
        let reply = if kind == Some(SIGN_REQUEST)
            && chosen.as_deref() != Some(take_string(&mut &request[1..])?)
        {
            vec![FAILURE]
        } else {
            write_frame(&mut upstream, &request)?;
            let reply = read_frame(&mut upstream)?.ok_or(io::ErrorKind::UnexpectedEof)?;
            let identities = match kind {
                Some(REQUEST_IDENTITIES) => parse_identities(&reply)?,
                _ => Vec::new(),
            };
            if identities.is_empty() {
                reply
            } else {
                let (tx, rx) = mpsc::channel();
                picks
                    .send(Request::Pick(Pick {
                        identities,
                        cwd: cwd.clone(),
                        repo: repo.clone(),
                        host: host.clone(),
                        reply: tx,
                    }))
                    .map_err(|_| io::Error::other("ui is gone"))?;
                match rx.recv().map_err(|_| io::Error::other("ui is gone"))? {
                    Some(identity) => {
                        let answer = identities_answer(&identity);
                        chosen = Some(identity.key_blob);
                        answer
                    }
                    // DRAFT: a cancel looks like an agent with no keys
                    None => vec![IDENTITIES_ANSWER, 0, 0, 0, 0],
                }
            }
        };
        write_frame(&mut client, &reply)?;
    }
    Ok(())
}

fn identities_answer(identity: &Identity) -> Vec<u8> {
    let mut out = vec![IDENTITIES_ANSWER];
    out.extend(1u32.to_be_bytes());
    put_string(&mut out, &identity.key_blob);
    put_string(&mut out, identity.comment.as_bytes());
    out
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
