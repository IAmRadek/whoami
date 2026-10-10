use raylib::ffi::CSSPalette;
use raylib::prelude::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod agent;
mod macos;

// one `git push` can open several agent connections; reuse a fresh choice for them
const REMEMBER: Duration = Duration::from_secs(1);

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
    rl.set_exit_key(None);
    let monitor = get_current_monitor();
    let (width, height) = ((get_monitor_width(monitor) as f32 * 0.6) as i32, 260);
    rl.set_window_size(width, height);
    rl.set_window_position(
        (get_monitor_width(monitor) - width) / 2,
        (get_monitor_height(monitor) - height) / 2,
    );

    let mut pending: Option<agent::Pick> = None;
    let mut last: Option<(Vec<u8>, Instant)> = None;
    let mut selected = 0;
    let mut progress = Vec::new();

    while !rl.window_should_close() {
        let dt = rl.get_frame_time();

        if pending.is_none() {
            if let Ok(mut pick) = picks.try_recv() {
                let remembered = last
                    .as_ref()
                    .filter(|(_, at)| at.elapsed() < REMEMBER)
                    .and_then(|(key, _)| pick.identities.iter().position(|i| &i.key_blob == key));
                match remembered {
                    Some(i) => {
                        let _ = pick.reply.send(Some(pick.identities.swap_remove(i)));
                    }
                    None => {
                        rl.clear_window_state(WindowState::default().set_window_hidden(true));
                        rl.set_window_focused();
                        selected = 0;
                        progress = vec![0.0f32; pick.identities.len()];
                        pending = Some(pick);
                    }
                }
            }
        }

        let enter = rl.is_key_pressed(KeyboardKey::KEY_ENTER);
        if enter || rl.is_key_pressed(KeyboardKey::KEY_ESCAPE) {
            if let Some(mut pick) = pending.take() {
                let identity = enter.then(|| pick.identities.swap_remove(selected));
                if let Some(identity) = &identity {
                    last = Some((identity.key_blob.clone(), Instant::now()));
                }
                let _ = pick.reply.send(identity);
            }
            rl.set_window_state(WindowState::default().set_window_hidden(true));
            macos::hide();
        }

        let Some(pick) = &pending else {
            rl.begin_drawing(&thread)
                .clear_background(Color::TRANSPARENT);
            continue;
        };
        let identities = &pick.identities;
        let n = identities.len();

        if rl.is_key_pressed(KeyboardKey::KEY_TAB) {
            selected = (selected + 1) % n;
        }

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
