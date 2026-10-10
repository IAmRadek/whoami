use raylib::ffi::CSSPalette;
use raylib::prelude::*;

fn main() {
    //.topmost().borderless_windowed_mode().undecorated()
    let (mut rl, thread) = raylib::init()
        .resizable()
        .transparent()
        .borderless_windowed_mode()
        .undecorated()
        .highdpi()
        .topmost()
        .build();
    let monitor = get_current_monitor();
    let (width, height) = ((get_monitor_width(monitor) as f32 * 0.6) as i32, 260);
    rl.set_window_size(width, height);
    rl.set_window_position(
        (get_monitor_width(monitor) - width) / 2,
        (get_monitor_height(monitor) - height) / 2,
    );

    let mut selected = 0;
    let mut progress = [0.0f32; 3];

    while !rl.window_should_close() {
        let dt = rl.get_frame_time();

        if rl.is_key_pressed(KeyboardKey::KEY_TAB) {
            selected = (selected + 1) % 3;
        }

        let (sw, sh) = (rl.get_screen_width() as f32, rl.get_screen_height() as f32);
        let header = sh * 0.25;
        let h = (sh - header) * 0.6;
        let w = h * 1.25;
        let gap = w * 0.2;
        let x0 = (sw - (3.0 * w + 2.0 * gap)) / 2.0;
        let y = header + (sh - header - h) / 2.0;

        let title = "SELECT SSH KEY";
        let font_size = (header * 0.4) as i32;
        let title_w = rl.measure_text(title, font_size) as f32;

        let mut d = rl.begin_drawing(&thread);
        d.clear_background(Color::TRANSPARENT);
        // roundness is relative to the shorter side, so scale it to match the cards' corner radius
        let panel_w = 4.0 * w + 4.0 * gap;
        let panel = Rectangle::new((sw - panel_w) / 2.0, 0.0, panel_w, sh);
        d.draw_rectangle_rounded(panel, 0.08 * h / sh, 16, Color::new(10, 12, 10, 255));
        d.draw_text(
            title,
            ((sw - title_w) / 2.0) as i32,
            ((header - font_size as f32) / 1.3) as i32,
            font_size,
            Color::new(51, 255, 102, 255),
        );

        for i in 0..3 {
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
            d.draw_rectangle_rounded_lines_ex(rec, 0.08, 16, 2.0, Color::new(51, 255, 102, (255.0 * eased) as u8));
        }
    }
}
