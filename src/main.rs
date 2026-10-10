use raylib::ffi::CSSPalette;
use raylib::prelude::*;

fn main() {
    //.topmost().borderless_windowed_mode().undecorated()
    let (mut rl, thread) = raylib::init().topmost().borderless_windowed_mode().undecorated().transparent().build();
    let monitor = get_current_monitor();
    let (width, height) = ((get_monitor_width(monitor) as f32 * 0.6) as i32, 200);
    rl.set_window_size(width, 200);
    rl.set_window_position(
        (get_monitor_width(monitor) - width) / 2,
        (get_monitor_height(monitor) - height) / 2,
    );

    while !rl.window_should_close() {
        let mouse = rl.get_mouse_position();
        let scroll = rl.get_mouse_wheel_move();

        let mut d = rl.begin_drawing(&thread);
        //d.clear_background(Color::TRANSPARENT);
        d.clear_background(Color::WHEAT);
        d.draw_text(
            &format!(
                "mouse: ({:.0}, {:.0})  scroll: {:.1}",
                mouse.x, mouse.y, scroll
            ),
            10,
            10,
            20,
            Color::WHITE,
        );
    }
}
