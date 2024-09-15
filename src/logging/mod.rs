#![allow(non_upper_case_globals)]

/// Credits to: https://github.com/eliasjonsson023/inline_colorization

pub const style_bold: &str = "\x1B[1m";
pub const style_un_bold: &str = "\x1B[21m";
pub const style_underline: &str = "\x1B[4m";
pub const style_un_underline: &str = "\x1B[24m";
pub const style_reset: &str = "\x1B[0m";
pub const color_black: &str = "\x1B[30m";
pub const color_red: &str = "\x1B[31m";
pub const color_green: &str = "\x1B[32m";
pub const color_yellow: &str = "\x1B[33m";
pub const color_blue: &str = "\x1B[34m";
pub const color_magenta: &str = "\x1B[35m";
pub const color_cyan: &str = "\x1B[36m";
pub const color_white: &str = "\x1B[37m";
pub const color_bright_black: &str = "\x1B[90m";
pub const color_bright_red: &str = "\x1B[91m";
pub const color_bright_green: &str = "\x1B[92m";
pub const color_bright_yellow: &str = "\x1B[93m";
pub const color_bright_blue: &str = "\x1B[94m";
pub const color_bright_magenta: &str = "\x1B[95m";
pub const color_bright_cyan: &str = "\x1B[96m";
pub const color_bright_white: &str = "\x1B[97m";
pub const color_reset: &str = "\x1B[39m";
pub const bg_black: &str = "\x1B[40m";
pub const bg_red: &str = "\x1B[41m";
pub const bg_green: &str = "\x1B[42m";
pub const bg_yellow: &str = "\x1B[43m";
pub const bg_blue: &str = "\x1B[44m";
pub const bg_magenta: &str = "\x1B[45m";
pub const bg_cyan: &str = "\x1B[46m";
pub const bg_white: &str = "\x1B[47m";
pub const bg_bright_black: &str = "\x1B[100m";
pub const bg_bright_red: &str = "\x1B[101m";
pub const bg_bright_green: &str = "\x1B[102m";
pub const bg_bright_yellow: &str = "\x1B[103m";
pub const bg_bright_blue: &str = "\x1B[104m";
pub const bg_bright_magenta: &str = "\x1B[105m";
pub const bg_bright_cyan: &str = "\x1B[106m";
pub const bg_bright_white: &str = "\x1B[107m";
pub const bg_reset: &str = "\x1B[49m";


#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
       println!(
            "{}{}{:<10}| {:<10} | {}{}",
            $crate::logging::color_bright_green,
            $crate::logging::style_bold,
            "info",
            $crate::START_TIME.elapsed().unwrap().as_millis(),
            $crate::logging::style_reset,
            format_args!($($arg)*)
        );
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        println!(
            "{}{}{:<10}| {:<10} | {}{}",
            $crate::logging::color_blue,
            $crate::logging::style_bold,
            "debug",
            $crate::START_TIME.elapsed().unwrap().as_millis(),
            $crate::logging::style_reset,
            format_args!($($arg)*)
        )
    };
}


#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
       println!(
            "{}{}{:<10}| {:<10} | {}{}",
            $crate::logging::color_bright_red,
            $crate::logging::style_bold,
            "error",
            $crate::START_TIME.elapsed().unwrap().as_millis(),
            $crate::logging::style_reset,
            format_args!($($arg)*)
        )
    };
}