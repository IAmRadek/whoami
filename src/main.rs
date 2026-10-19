use raylib::ffi::CSSPalette;
use raylib::prelude::*;
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod agent;
mod macos;

// one `git push` can open several agent connections; reuse a fresh choice for them
const REMEMBER: Duration = Duration::from_secs(10);

// the key for a directory, from `<directory prefix>=<key>` lines in ~/.ssh/whoami.cfg;
// the longest matching prefix wins, and the last of equal ones
fn rule_for(cwd: &Path) -> Option<String> {
    let Ok(home) = std::env::var("HOME") else {
        eprintln!("whoami: rules: HOME is not set");
        return None;
    };
    let path = Path::new(&home).join(".ssh/whoami.cfg");
    let config = match std::fs::read_to_string(&path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("whoami: rules: {}: {e}", path.display());
            return None;
        }
    };
    eprintln!("whoami: rules: {} for {}", path.display(), cwd.display());
    let cwd = cwd.as_os_str().as_bytes();
    let mut best: Option<(String, &str)> = None;
    for (n, line) in config.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((dir, key)) = line.split_once('=') else {
            eprintln!("whoami: rules: line {}: no '=', skipped: {line:?}", n + 1);
            continue;
        };
        let dir = dir.trim();
        let dir = match dir.strip_prefix('~') {
            Some(rest) => format!("{home}{rest}"),
            None => dir.to_string(),
        };
        let key = key.trim();
        let matches = cwd.starts_with(dir.as_bytes());
        eprintln!(
            "whoami: rules: line {}: {dir:?} = {key:?}{}",
            n + 1,
            if matches { ", matches" } else { "" }
        );
        if matches && best.as_ref().is_none_or(|(b, _)| dir.len() >= b.len()) {
            best = Some((dir, key));
        }
    }
    match &best {
        Some((dir, key)) => eprintln!("whoami: rules: {dir:?} chooses {key:?}"),
        None => eprintln!("whoami: rules: no rule matches"),
    }
    best.map(|(_, key)| key.to_string())
}

// a rule names a key by its fingerprint, as `ssh-add -l` prints it, or else by its comment
fn names(key: &str, identity: &agent::Identity) -> bool {
    if key.starts_with("SHA256:") {
        key == fingerprint(&identity.key_blob)
    } else {
        key == identity.comment
    }
}

// SHA256:, then the hash of the key blob in base64 with no padding
fn fingerprint(key_blob: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::from("SHA256:");
    for chunk in Sha256::digest(key_blob).chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &b| n << 8 | b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(BASE64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn main() {
    let upstream = std::env::var("WHOAMI_UPSTREAM")
        .or_else(|_| std::env::var("SSH_AUTH_SOCK"))
        .expect("set WHOAMI_UPSTREAM or SSH_AUTH_SOCK");

    let socket = std::env::var("WHOAMI_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("whoami.sock"));
    let listener = agent::listen(&socket).expect("bind agent socket");
    eprintln!("whoami: listening on {}", socket.display());
    let (pick_tx, picks) = mpsc::channel();
    std::thread::spawn(move || agent::serve(listener, upstream, pick_tx));

    let (mut rl, thread) = raylib::init()
        .resizable()
        .transparent()
        .borderless_windowed_mode()
        .undecorated()
        .hidden()
        .highdpi()
        .topmost()
        .build();
    macos::set_accessory();
    unsafe { macos::move_to_active_space(rl.get_window_handle()) };
    rl.set_exit_key(None);
    rl.set_target_fps(60);
    let monitor = get_current_monitor();
    let (width, height) = ((get_monitor_width(monitor) as f32 * 0.6) as i32, 260);
    rl.set_window_size(width, height);
    rl.set_window_position(
        (get_monitor_width(monitor) - width) / 2,
        (get_monitor_height(monitor) - height) / 2,
    );

    let mut pending: Option<agent::Pick> = None;
    let mut error: Option<&str> = None;
    let mut last: Option<(Vec<u8>, Instant)> = None;
    // key blobs, most recently chosen first
    let mut recent: Vec<Vec<u8>> = Vec::new();
    let mut selected = 0;
    // set where the cards are drawn and confirmed on the next frame
    let mut clicked = false;
    let mut progress = Vec::new();

    while !rl.window_should_close() {
        // the first frames after a wait for the proxy report the whole wait
        let dt = rl.get_frame_time().min(1.0 / 30.0);

        if pending.is_none() {
            let request = match error {
                // nothing is on screen, so draw no frames until the proxy asks for something
                None => match picks.recv() {
                    Ok(request) => Ok(request),
                    Err(_) => break,
                },
                Some(_) => picks.try_recv(),
            };
            match request {
                Ok(agent::Request::Unavailable) => {
                    rl.clear_window_state(WindowState::default().set_window_hidden(true));
                    rl.set_window_focused();
                    error = Some("ssh-agent not available");
                }
                Ok(agent::Request::Pick(mut pick)) => {
                    let ruled = pick.cwd.as_deref().and_then(rule_for).and_then(|key| {
                        let found = pick.identities.iter().position(|i| names(&key, i));
                        if found.is_none() {
                            eprintln!("whoami: rules: the agent has no key {key:?}, only:");
                            for i in &pick.identities {
                                eprintln!("whoami:   {} {}", fingerprint(&i.key_blob), i.comment);
                            }
                        }
                        found
                    });
                    let remembered = last
                        .as_ref()
                        .filter(|(_, at)| at.elapsed() < REMEMBER)
                        .and_then(|(key, _)| {
                            pick.identities.iter().position(|i| &i.key_blob == key)
                        });
                    match ruled.or(remembered) {
                        Some(i) => {
                            let how = if ruled.is_some() { "rule" } else { "last choice" };
                            eprintln!("whoami: offers {:?} by {how}", pick.identities[i].comment);
                            let _ = pick.reply.send(Some(pick.identities.swap_remove(i)));
                        }
                        None => {
                            eprintln!("whoami: shows the picker");
                            rl.clear_window_state(WindowState::default().set_window_hidden(true));
                            rl.set_window_focused();
                            error = None;
                            // stable sort: keys never chosen keep the upstream order, after the used ones
                            pick.identities.sort_by_key(|i| {
                                recent
                                    .iter()
                                    .position(|k| k == &i.key_blob)
                                    .unwrap_or(usize::MAX)
                            });
                            selected = 0;
                            progress = vec![0.0f32; pick.identities.len()];
                            pending = Some(pick);
                        }
                    }
                }
                Err(_) => {}
            }
        }

        let enter = rl.is_key_pressed(KeyboardKey::KEY_ENTER) || std::mem::take(&mut clicked);
        if enter || rl.is_key_pressed(KeyboardKey::KEY_ESCAPE) {
            if let Some(mut pick) = pending.take() {
                let identity = enter.then(|| pick.identities.swap_remove(selected));
                if let Some(identity) = &identity {
                    last = Some((identity.key_blob.clone(), Instant::now()));
                    recent.retain(|k| k != &identity.key_blob);
                    recent.insert(0, identity.key_blob.clone());
                }
                let _ = pick.reply.send(identity);
            }
            error = None;
            rl.set_window_state(WindowState::default().set_window_hidden(true));
            macos::hide();
        }

        if let Some(message) = error {
            let (sw, sh) = (rl.get_screen_width() as f32, rl.get_screen_height() as f32);
            let size = sh * 0.1;
            let text_w = rl.measure_text(message, size as i32) as f32;
            let mut d = rl.begin_drawing(&thread);
            d.clear_background(Color::TRANSPARENT);
            let pill = Rectangle::new(
                (sw - text_w) / 2.0 - size,
                (sh - 3.0 * size) / 2.0,
                text_w + 2.0 * size,
                3.0 * size,
            );
            d.draw_rectangle_rounded(pill, 0.3, 16, Color::new(10, 12, 10, 255));
            d.draw_text(
                message,
                ((sw - text_w) / 2.0) as i32,
                ((sh - size) / 2.0) as i32,
                size as i32,
                Color::new(255, 85, 85, 255),
            );
            continue;
        }

        let Some(pick) = &pending else {
            rl.begin_drawing(&thread)
                .clear_background(Color::TRANSPARENT);
            continue;
        };
        let identities = &pick.identities;
        let n = identities.len();

        if rl.is_key_pressed(KeyboardKey::KEY_TAB) || rl.is_key_pressed(KeyboardKey::KEY_RIGHT) {
            selected = (selected + 1) % n;
        }
        if rl.is_key_pressed(KeyboardKey::KEY_LEFT) {
            selected = (selected + n - 1) % n;
        }
        let mouse = rl.get_mouse_position();
        let delta = rl.get_mouse_delta();
        // a resting cursor leaves the keyboard highlight alone
        let moved = delta.x != 0.0 || delta.y != 0.0;
        let click = rl.is_mouse_button_pressed(MouseButton::MOUSE_BUTTON_LEFT);

        let (sw, sh) = (rl.get_screen_width() as f32, rl.get_screen_height() as f32);
        let header = sh * 0.25;
        let h = (sh - header) * 0.6;
        let w = h * 1.25;
        let gap = w * 0.2;
        let x0 = (sw - (n as f32 * w + (n - 1) as f32 * gap)) / 2.0;
        let y = header + (sh - header - h) / 2.0;

        let title = "SELECT SSH KEY";
        let font_size = (header * 0.4) as i32;
        let title_w = rl.measure_text(title, font_size) as f32;

        let mut d = rl.begin_drawing(&thread);
        d.clear_background(Color::TRANSPARENT);
        // roundness is relative to the shorter side, so scale it to match the cards' corner radius
        let panel_w = (n + 1) as f32 * (w + gap);
        let panel = Rectangle::new((sw - panel_w) / 2.0, 0.0, panel_w, sh);
        d.draw_rectangle_rounded(panel, 0.08 * h / sh, 16, Color::new(10, 12, 10, 255));
        d.draw_text(
            title,
            ((sw - title_w) / 2.0) as i32,
            ((header - font_size as f32) / 1.3) as i32,
            font_size,
            Color::new(51, 255, 102, 255),
        );

        for (i, identity) in identities.iter().enumerate() {
            let mut rec = Rectangle::new(x0 + i as f32 * (w + gap), y, w, h);

            let dir = if i == selected { 1.0 } else { -1.0 };
            progress[i] = (progress[i] + dir * dt / 0.2).clamp(0.0, 1.0);
            let p = progress[i];
            let eased = if p < 0.5 {
                4.0 * p * p * p
            } else {
                1.0 - (-2.0 * p + 2.0).powi(3) / 2.0
            }; // ease-in-out cubic
            let scale = 1.0 + 0.2 * eased;

            rec.x -= w * (scale - 1.0) / 2.0;
            rec.y -= h * (scale - 1.0) / 2.0;
            rec.width *= scale;
            rec.height *= scale;

            let over = (rec.x..rec.x + rec.width).contains(&mouse.x)
                && (rec.y..rec.y + rec.height).contains(&mouse.y);
            if over && (moved || click) {
                selected = i;
            }
            if over && click {
                clicked = true;
            }

            d.draw_rectangle_rounded(rec, 0.08, 16, Color::new(18, 24, 18, 255));
            d.draw_rectangle_rounded_lines_ex(
                rec,
                0.08,
                16,
                2.0,
                Color::new(51, 255, 102, (255.0 * eased) as u8),
            );

            let label_size = (h * 0.12) as i32;
            let label_w = d.measure_text(&identity.comment, label_size) as f32;
            d.draw_text(
                &identity.comment,
                (rec.x + (rec.width - label_w) / 2.0) as i32,
                (rec.y + (rec.height - label_size as f32) / 2.0) as i32,
                label_size,
                Color::new(51, 255, 102, 255),
            );
        }
    }
}
