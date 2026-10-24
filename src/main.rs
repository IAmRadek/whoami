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

// the key for a client, from lines in ~/.ssh/whoami.cfg: `<directory prefix>=<key>` matches
// the client's directory, `repo:<repository prefix>=<key>` matches its repository, and
// `host:<host prefix>=<key>` matches its ssh host; the most specific kind wins, a directory
// over a repository over a host, then the longest prefix, then the last line
fn rule_for(cwd: Option<&Path>, repo: Option<&str>, host: Option<&str>) -> Option<String> {
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
    eprintln!(
        "whoami: rules: {} for {cwd:?}, repository {repo:?} and host {host:?}",
        path.display()
    );
    let mut best: Option<((u8, usize), &str, &str)> = None;
    for (n, line) in config.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((dir, key)) = line.split_once('=') else {
            eprintln!("whoami: rules: line {}: no '=', skipped: {line:?}", n + 1);
            continue;
        };
        let (rule, key) = (dir.trim(), key.trim());
        let (rank, prefix, matches) = match (rule.strip_prefix("repo:"), rule.strip_prefix("host:"))
        {
            (Some(prefix), _) => (
                (1, prefix.len()),
                prefix.to_string(),
                repo.is_some_and(|repo| repo.starts_with(prefix)),
            ),
            (_, Some(prefix)) => (
                (0, prefix.len()),
                prefix.to_string(),
                host.is_some_and(|host| host.starts_with(prefix)),
            ),
            (None, None) => {
                let prefix = match rule.strip_prefix('~') {
                    Some(rest) => format!("{home}{rest}"),
                    None => rule.to_string(),
                };
                let matches = cwd
                    .is_some_and(|cwd| cwd.as_os_str().as_bytes().starts_with(prefix.as_bytes()));
                ((2, prefix.len()), prefix, matches)
            }
        };
        eprintln!(
            "whoami: rules: line {}: {rule:?} as {prefix:?} = {key:?}{}",
            n + 1,
            if matches { ", matches" } else { "" }
        );
        if matches && best.as_ref().is_none_or(|(b, _, _)| rank >= *b) {
            best = Some((rank, rule, key));
        }
    }
    match &best {
        Some((_, rule, key)) => eprintln!("whoami: rules: {rule:?} chooses {key:?}"),
        None => eprintln!("whoami: rules: no rule matches"),
    }
    best.map(|(_, _, key)| key.to_string())
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
    let (width, height) = ((get_monitor_width(monitor) as f32 * 0.6) as i32, 340);
    rl.set_window_size(width, height);
    rl.set_window_position(
        (get_monitor_width(monitor) - width) / 2,
        (get_monitor_height(monitor) - height) / 2,
    );
    // Doto, a dot-matrix font under the OFL (src/font/OFL.txt), built into the binary;
    // loaded at twice the drawn size for the high-DPI framebuffer
    let font = rl
        .load_font_from_memory(
            &thread,
            ".ttf",
            include_bytes!("font/static/Doto-Bold.ttf"),
            40,
            None,
        )
        .map(|font| {
            font.texture()
                .set_texture_filter(&thread, TextureFilter::TEXTURE_FILTER_BILINEAR);
            font.make_weak()
        })
        .unwrap_or_else(|e| {
            eprintln!("whoami: font: {e}, drawing with raylib's default");
            rl.get_font_default()
        });

    let mut pending: Option<agent::Pick> = None;
    let mut error: Option<&str> = None;
    let mut last: Option<(Vec<u8>, Instant)> = None;
    // key blobs, most recently chosen first
    let mut recent: Vec<Vec<u8>> = Vec::new();
    let mut selected = 0;
    // set where the cards are drawn and confirmed on the next frame
    let mut clicked = false;
    let mut progress = Vec::new();
    // when the picker last appeared, for the prompt typing out
    let mut shown = Instant::now();

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
                    let ruled = rule_for(
                        pick.cwd.as_deref(),
                        pick.repo.as_deref(),
                        pick.host.as_deref(),
                    )
                    .and_then(|key| {
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
                            let how = if ruled.is_some() {
                                "rule"
                            } else {
                                "last choice"
                            };
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
                            shown = Instant::now();
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

        const GREEN: Color = Color::new(51, 255, 102, 255);
        const DIM: Color = Color::new(51, 255, 102, 120);
        let sw = rl.get_screen_width() as f32;
        let sh = rl.get_screen_height() as f32;
        let size = 20.0;
        let line = size * 1.4;
        let pad = size * 1.2;
        let measure = |text: &str| font.measure_text(text, size, 0.0).x;
        let since = shown.elapsed().as_secs_f32();

        let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        let prompt = format!("{user}@whoami:~$ ");
        let command = "select-key";
        // the command types out at 50 characters a second, then the rest of the screen appears
        let typed = ((since * 50.0) as usize).min(command.len());
        let done = typed == command.len();
        let cursor = if (since * 2.0) as u32 % 2 == 0 {
            "_"
        } else {
            ""
        };

        // the values rules match on, written as a rule in ~/.ssh/whoami.cfg would write them
        let dir = pick.cwd.as_deref().map_or("-".to_string(), |cwd| {
            let cwd = cwd.display().to_string();
            match std::env::var("HOME") {
                Ok(home) if cwd.starts_with(&home) => format!("~{}", &cwd[home.len()..]),
                _ => cwd,
            }
        });
        let rows = [
            ("dir", dir.as_str()),
            ("host", pick.host.as_deref().unwrap_or("-")),
            ("repo", pick.repo.as_deref().unwrap_or("-")),
        ];
        let hint = "tab/arrows move    enter select    esc cancel";

        let mut d = rl.begin_drawing(&thread);
        d.clear_background(Color::TRANSPARENT);

        let column = measure("host  ");
        let gap = measure("   ");
        // laid out by the selected form, so moving the selection keeps every key in place
        let widths: Vec<f32> = identities
            .iter()
            .map(|i| measure(&format!("[>{}<]", i.comment)))
            .collect();
        let content_w = [
            measure(&format!("{prompt}{command}_")),
            rows.iter()
                .map(|(_, value)| column + measure(value))
                .fold(0.0, f32::max),
            widths.iter().sum::<f32>() + (n - 1) as f32 * gap,
            measure(hint),
        ]
        .into_iter()
        .fold(0.0, f32::max);
        let panel_w = (content_w + 2.0 * pad).min(sw);
        let panel = Rectangle::new((sw - panel_w) / 2.0, 0.0, panel_w, sh);
        d.draw_rectangle_rec(panel, Color::new(10, 12, 10, 255));
        d.draw_rectangle_lines_ex(panel, 1.0, DIM);

        let x = panel.x + pad;
        let mut y = pad;
        d.draw_text_ex(&font, &prompt, Vector2::new(x, y), size, 0.0, DIM);
        d.draw_text_ex(
            &font,
            &format!("{}{cursor}", &command[..typed]),
            Vector2::new(x + measure(&prompt), y),
            size,
            0.0,
            GREEN,
        );

        if done {
            y += 1.5 * line;
            for (label, value) in rows {
                d.draw_text_ex(&font, label, Vector2::new(x, y), size, 0.0, DIM);
                d.draw_text_ex(&font, value, Vector2::new(x + column, y), size, 0.0, GREEN);
                y += line;
            }

            y += line;
            let mut kx = x;
            for (i, identity) in identities.iter().enumerate() {
                // three rows tall, with the label in the middle
                let rec = Rectangle::new(kx - 4.0, y, widths[i] + 8.0, 3.0 * line);
                kx += widths[i] + gap;

                let dir = if i == selected { 1.0 } else { -1.0 };
                progress[i] = (progress[i] + dir * dt / 0.2).clamp(0.0, 1.0);
                let p = progress[i];
                let eased = if p < 0.5 {
                    4.0 * p * p * p
                } else {
                    1.0 - (-2.0 * p + 2.0).powi(3) / 2.0
                }; // ease-in-out cubic

                let over = (rec.x..rec.x + rec.width).contains(&mouse.x)
                    && (rec.y..rec.y + rec.height).contains(&mouse.y);
                if over && (moved || click) {
                    selected = i;
                }
                if over && click {
                    clicked = true;
                }

                let label = if i == selected {
                    format!("[>{}<]", identity.comment)
                } else {
                    format!("[ {} ]", identity.comment)
                };
                d.draw_rectangle_rec(rec, Color::new(51, 255, 102, (50.0 * eased) as u8));
                d.draw_text_ex(
                    &font,
                    &label,
                    Vector2::new(
                        rec.x + (rec.width - measure(&label)) / 2.0,
                        rec.y + (rec.height - size) / 2.0,
                    ),
                    size,
                    0.0,
                    Color::new(51, 255, 102, (120.0 + 135.0 * eased) as u8),
                );
            }

            let hint_at = Vector2::new(x, sh - pad - size);
            d.draw_text_ex(&font, hint, hint_at, size, 0.0, DIM);
        }

        // CRT scanlines over the whole panel
        for row in (0..sh as i32).step_by(3) {
            d.draw_line(
                panel.x as i32,
                row,
                (panel.x + panel.width) as i32,
                row,
                Color::new(0, 0, 0, 60),
            );
        }
    }
}
