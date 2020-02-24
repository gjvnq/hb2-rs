extern crate log;

use env_logger::{Env, Builder, fmt::{Color, Style, StyledValue}};
use log::Level;
use chrono::Local;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;

pub fn colored_level<'a>(style: &'a mut Style, level: Level) -> StyledValue<'a, &'static str> {
    match level {
        Level::Trace => style.set_color(Color::Magenta).set_bold(true).value("TRACE"),
        Level::Debug => style.set_color(Color::Blue).set_bold(true).value("DEBUG"),
        Level::Info => style.set_color(Color::Green).set_bold(true).value("INFO "),
        Level::Warn => style.set_color(Color::Yellow).set_bold(true).value("WARN "),
        Level::Error => style.set_color(Color::Red).set_bold(true).value("ERROR"),
    }
}

pub fn start_logger() {
    let env = Env::new().filter_or("HB2_LOG", "info");

    let mut builder = Builder::from_env(env);
    builder.format(|final_buf, record| {

        let mut style = final_buf.style();
        let level = colored_level(&mut style, record.level());
        let mut buf1 = String::new();
        write!(buf1,
            "{}",
            Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string()).unwrap();
        let mut buf2 = String::new();
        write!(buf2,
            "{}:{}:{}",
            record.module_path().unwrap_or_default(),
            record.file().unwrap_or_default(),
            record.line().unwrap_or_default()).unwrap();

        let mut style = final_buf.style();
        let base1 = style.set_color(Color::Ansi256(250)).value(buf1);
        let mut style = final_buf.style();
        let base2 = style.set_color(Color::Ansi256(250)).value(buf2);
        let mut style = final_buf.style();
        let base3 = style.set_color(Color::Ansi256(250)).set_bold(true).value(">");
        writeln!(final_buf,
            "{} {} {} {} {}",
            base1,
            level,
            base2,
            base3,
            record.args())
            // let buf.style().set_color(Color::Magenta);
        }).init();
}