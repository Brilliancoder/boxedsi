// A release build on Windows is a window program: without this line a console window opens behind the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    boxed_desktop_lib::run()
}
