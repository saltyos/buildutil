//! SPDX-License-Identifier: GPL-2.0-only
//! Configuration editor terminal: raw mode, screen modes, size, and key input
//!
//! `Tty` puts the controlling terminal into raw mode on the alternate
//! screen and restores every change on drop, on suspend, and on error
//! paths. Signals are not used: `ISIG` is off, so Ctrl-C and Ctrl-Z arrive
//! as keys, and reads time out every 100 ms so a resize is noticed by
//! polling the window size. `Decoder` turns the byte stream into keys; it
//! is pure so fragmented and coalesced input can be tested.

/// One decoded input event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Delete,
    Enter,
    Tab,
    Backspace,
    Esc,
    Char(char),
    /// Ctrl plus a letter, lowercase.
    Ctrl(char),
    /// A terminal's answer to the OSC 11 background query.
    Background(u8, u8, u8),
}

/// Incremental key decoder. Bytes are fed as they arrive; `next` yields a
/// key once a complete sequence is buffered. `idle` says no further bytes
/// arrived within the read timeout, which settles a lone ESC as the Esc key
/// and drops a sequence that never completed.
#[derive(Debug, Default)]
pub struct Decoder {
    pending: Vec<u8>,
}

/// Longest escape sequence kept while waiting for its terminator.
const MAX_SEQUENCE: usize = 256;

impl Decoder {
    pub fn feed(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    pub fn next(&mut self, idle: bool) -> Option<Key> {
        loop {
            let first = *self.pending.first()?;
            match self.parse(first, idle) {
                Parse::Key(key, used) => {
                    self.pending.drain(..used);
                    return Some(key);
                }
                Parse::Skip(used) => {
                    self.pending.drain(..used);
                }
                Parse::Wait => return None,
            }
        }
    }

    fn parse(&self, first: u8, idle: bool) -> Parse {
        let p = &self.pending;
        let incomplete = |p: &Vec<u8>| {
            if idle || p.len() > MAX_SEQUENCE {
                Parse::Skip(p.len())
            } else {
                Parse::Wait
            }
        };
        match first {
            0x1b => {
                let Some(&second) = p.get(1) else {
                    return if idle {
                        Parse::Key(Key::Esc, 1)
                    } else {
                        Parse::Wait
                    };
                };
                match second {
                    b'[' => match p[2..].iter().position(|b| (0x40..=0x7e).contains(b)) {
                        Some(i) => {
                            let end = 2 + i;
                            let params = &p[2..end];
                            match csi_key(params, p[end]) {
                                Some(key) => Parse::Key(key, end + 1),
                                None => Parse::Skip(end + 1),
                            }
                        }
                        None => incomplete(p),
                    },
                    b'O' => match p.get(2) {
                        Some(&b) => match ss3_key(b) {
                            Some(key) => Parse::Key(key, 3),
                            None => Parse::Skip(3),
                        },
                        None => incomplete(p),
                    },
                    b']' => match osc_end(p) {
                        Some((body_end, used)) => match parse_background(&p[2..body_end]) {
                            Some((r, g, b)) => Parse::Key(Key::Background(r, g, b), used),
                            None => Parse::Skip(used),
                        },
                        None => incomplete(p),
                    },
                    // Alt-modified keys are not bound; report the Esc.
                    _ => Parse::Key(Key::Esc, 1),
                }
            }
            b'\r' | b'\n' => Parse::Key(Key::Enter, 1),
            0x7f | 0x08 => Parse::Key(Key::Backspace, 1),
            b'\t' => Parse::Key(Key::Tab, 1),
            0x01..=0x1a => Parse::Key(Key::Ctrl((b'a' + first - 1) as char), 1),
            0x00..=0x1f => Parse::Skip(1),
            _ => {
                let len = utf8_len(first);
                if len == 0 {
                    return Parse::Skip(1);
                }
                if p.len() < len {
                    return incomplete(p);
                }
                match std::str::from_utf8(&p[..len])
                    .ok()
                    .and_then(|s| s.chars().next())
                {
                    Some(c) => Parse::Key(Key::Char(c), len),
                    None => Parse::Skip(1),
                }
            }
        }
    }
}

enum Parse {
    Key(Key, usize),
    Skip(usize),
    Wait,
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x20..=0x7e => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

fn csi_key(params: &[u8], fin: u8) -> Option<Key> {
    Some(match fin {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        b'~' => match params.split(|b| *b == b';').next()? {
            b"1" | b"7" => Key::Home,
            b"4" | b"8" => Key::End,
            b"3" => Key::Delete,
            b"5" => Key::PageUp,
            b"6" => Key::PageDown,
            _ => return None,
        },
        _ => return None,
    })
}

fn ss3_key(b: u8) -> Option<Key> {
    Some(match b {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        _ => return None,
    })
}

/// End of an OSC sequence: (end of body, bytes consumed). Terminated by BEL
/// or by ST (`ESC \`).
fn osc_end(p: &[u8]) -> Option<(usize, usize)> {
    for i in 2..p.len() {
        if p[i] == 0x07 {
            return Some((i, i + 1));
        }
        if p[i] == 0x1b && p.get(i + 1) == Some(&b'\\') {
            return Some((i, i + 2));
        }
    }
    None
}

/// `11;rgb:RRRR/GGGG/BBBB` (1–4 hex digits per channel) to 8-bit channels.
fn parse_background(body: &[u8]) -> Option<(u8, u8, u8)> {
    let body = std::str::from_utf8(body).ok()?;
    let spec = body.strip_prefix("11;rgb:")?;
    let mut channels = spec.split('/').map(|hex| {
        if hex.is_empty() || hex.len() > 4 {
            return None;
        }
        let v = u32::from_str_radix(hex, 16).ok()?;
        let max = (1u32 << (4 * hex.len())) - 1;
        Some(((v * 255 + max / 2) / max) as u8)
    });
    let r = channels.next()??;
    let g = channels.next()??;
    let b = channels.next()??;
    Some((r, g, b))
}

pub use sys::{Tty, terminated};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sys {
    use std::io::Write;

    #[cfg(target_os = "linux")]
    mod consts {
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: u32,
            pub c_oflag: u32,
            pub c_cflag: u32,
            pub c_lflag: u32,
            pub c_line: u8,
            pub c_cc: [u8; 32],
            pub c_ispeed: u32,
            pub c_ospeed: u32,
        }
        pub type Flag = u32;
        pub const ICRNL: Flag = 0o400;
        pub const IXON: Flag = 0o2000;
        pub const OPOST: Flag = 0o1;
        pub const ISIG: Flag = 0o1;
        pub const ICANON: Flag = 0o2;
        pub const ECHO: Flag = 0o10;
        pub const IEXTEN: Flag = 0o100000;
        pub const VTIME: usize = 5;
        pub const VMIN: usize = 6;
        pub const TIOCGWINSZ: u64 = 0x5413;
        pub const SIGTSTP: i32 = 20;
    }

    #[cfg(target_os = "macos")]
    mod consts {
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct Termios {
            pub c_iflag: u64,
            pub c_oflag: u64,
            pub c_cflag: u64,
            pub c_lflag: u64,
            pub c_cc: [u8; 20],
            pub c_ispeed: u64,
            pub c_ospeed: u64,
        }
        pub type Flag = u64;
        pub const ICRNL: Flag = 0x100;
        pub const IXON: Flag = 0x200;
        pub const OPOST: Flag = 0x1;
        pub const ISIG: Flag = 0x80;
        pub const ICANON: Flag = 0x100;
        pub const ECHO: Flag = 0x8;
        pub const IEXTEN: Flag = 0x400;
        pub const VTIME: usize = 17;
        pub const VMIN: usize = 16;
        pub const TIOCGWINSZ: u64 = 0x4008_7468;
        pub const SIGTSTP: i32 = 18;
    }

    use consts::*;

    #[repr(C)]
    struct Winsize {
        rows: u16,
        cols: u16,
        xpixel: u16,
        ypixel: u16,
    }

    // SAFETY: libc terminal calls on the standard descriptors; every buffer
    // passed is a valid, correctly sized Rust value.
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
        fn tcgetattr(fd: i32, termios: *mut Termios) -> i32;
        fn tcsetattr(fd: i32, action: i32, termios: *const Termios) -> i32;
        fn ioctl(fd: i32, request: u64, ...) -> i32;
        fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
        fn kill(pid: i32, sig: i32) -> i32;
        fn signal(signum: i32, handler: usize) -> usize;
    }

    const SIGHUP: i32 = 1;
    const SIGTERM: i32 = 15;
    const SIG_ERR: usize = usize::MAX;

    static TERMINATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    extern "C" fn on_terminate(_signum: i32) {
        TERMINATED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether SIGTERM or SIGHUP asked the editor to exit.
    pub fn terminated() -> bool {
        TERMINATED.load(std::sync::atomic::Ordering::SeqCst)
    }

    const TCSAFLUSH: i32 = 2;
    const ENTER_SCREEN: &str = "\x1b[?1049h\x1b[?25l\x1b[?7l";
    const LEAVE_SCREEN: &str = "\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l";

    /// The terminal in raw mode on the alternate screen. Dropping it puts
    /// back the saved attributes, the cursor, autowrap, and the main screen.
    pub struct Tty {
        saved: Termios,
        active: bool,
        /// Dispositions of SIGTERM and SIGHUP before the editor caught them.
        previous: [(i32, usize); 2],
    }

    impl Tty {
        pub fn open() -> Result<Tty, String> {
            // SAFETY: isatty only inspects the descriptor.
            if unsafe { isatty(0) } != 1 || unsafe { isatty(1) } != 1 {
                return Err("menuconfig needs an interactive terminal".to_string());
            }
            // SAFETY: zeroed Termios is a valid buffer for tcgetattr to fill.
            let mut saved: Termios = unsafe { std::mem::zeroed() };
            // SAFETY: fd 0 is a terminal (checked above); &mut saved is valid.
            if unsafe { tcgetattr(0, &mut saved) } != 0 {
                return Err("cannot read terminal attributes".to_string());
            }
            // SIGTERM and SIGHUP end the editor through the event loop, so
            // the terminal is restored; `ISIG` is off, so no other signal
            // arrives from the keyboard.
            let mut previous = [(0, SIG_ERR); 2];
            for (idx, sig) in [SIGTERM, SIGHUP].into_iter().enumerate() {
                // SAFETY: the handler has the C ABI and only stores a flag.
                previous[idx] = (sig, unsafe {
                    signal(sig, on_terminate as *const () as usize)
                });
            }
            let mut tty = Tty {
                saved,
                active: false,
                previous,
            };
            tty.enter()?;
            Ok(tty)
        }

        fn enter(&mut self) -> Result<(), String> {
            let mut raw = self.saved;
            raw.c_iflag &= !(ICRNL | IXON);
            raw.c_oflag &= !OPOST;
            raw.c_lflag &= !(ECHO | ICANON | ISIG | IEXTEN);
            raw.c_cc[VMIN] = 0;
            raw.c_cc[VTIME] = 1;
            // SAFETY: fd 0 is a terminal; &raw is a valid Termios.
            if unsafe { tcsetattr(0, TCSAFLUSH, &raw) } != 0 {
                return Err("cannot enter raw mode".to_string());
            }
            self.active = true;
            self.write(ENTER_SCREEN);
            Ok(())
        }

        fn leave(&mut self) {
            if !self.active {
                return;
            }
            self.write(LEAVE_SCREEN);
            // SAFETY: restores the attributes read in `open` on fd 0.
            unsafe {
                tcsetattr(0, TCSAFLUSH, &self.saved);
            }
            self.active = false;
        }

        /// Hand the terminal back, stop as Ctrl-Z would, and take the
        /// terminal again once the shell resumes the job.
        pub fn suspend(&mut self) -> Result<(), String> {
            self.leave();
            // The whole foreground process group stops, as with a Ctrl-Z
            // the terminal delivers: a parent waiting on this editor (buildutil
            // config) stops too, so the shell sees a stopped job.
            // SAFETY: pid 0 addresses this process's own group; execution
            // continues here on SIGCONT.
            unsafe {
                kill(0, SIGTSTP);
            }
            self.enter()
        }

        /// (columns, rows); 80×24 when the size is unknown.
        pub fn size(&self) -> (usize, usize) {
            let mut ws = Winsize {
                rows: 0,
                cols: 0,
                xpixel: 0,
                ypixel: 0,
            };
            // SAFETY: TIOCGWINSZ fills a struct winsize through the pointer.
            let ok = unsafe { ioctl(1, TIOCGWINSZ, &mut ws as *mut Winsize) } == 0;
            if ok && ws.cols > 0 && ws.rows > 0 {
                (ws.cols as usize, ws.rows as usize)
            } else {
                (80, 24)
            }
        }

        /// Read available input; returns 0 when the 100 ms timeout passes
        /// without input.
        pub fn read(&self, buf: &mut [u8]) -> usize {
            // SAFETY: buf is a valid writable buffer of buf.len() bytes.
            let n = unsafe { read(0, buf.as_mut_ptr(), buf.len()) };
            n.max(0) as usize
        }

        pub fn write(&self, text: &str) {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        }
    }

    impl Drop for Tty {
        fn drop(&mut self) {
            self.leave();
            for (sig, handler) in self.previous {
                if handler != SIG_ERR {
                    // SAFETY: restores the disposition `open` replaced.
                    unsafe {
                        signal(sig, handler);
                    }
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod sys {
    /// No terminal backend exists for this host; menuconfig reports that
    /// instead of starting.
    pub struct Tty;

    impl Tty {
        pub fn open() -> Result<Tty, String> {
            Err("menuconfig supports Linux and macOS terminals only".to_string())
        }

        pub fn suspend(&mut self) -> Result<(), String> {
            Ok(())
        }

        pub fn size(&self) -> (usize, usize) {
            (80, 24)
        }

        pub fn read(&self, _buf: &mut [u8]) -> usize {
            0
        }

        pub fn write(&self, _text: &str) {}
    }

    pub fn terminated() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(chunks: &[&[u8]], idle_after_each: bool) -> Vec<Key> {
        let mut d = Decoder::default();
        let mut out = Vec::new();
        for chunk in chunks {
            d.feed(chunk);
            while let Some(k) = d.next(false) {
                out.push(k);
            }
            if idle_after_each {
                while let Some(k) = d.next(true) {
                    out.push(k);
                }
            }
        }
        out
    }

    #[test]
    fn coalesced_keys_are_all_delivered() {
        assert_eq!(
            keys(&[b"jj\x1b[Bq"], false),
            vec![Key::Char('j'), Key::Char('j'), Key::Down, Key::Char('q')]
        );
    }

    #[test]
    fn fragmented_escape_sequences_wait_for_their_tail() {
        assert_eq!(keys(&[b"\x1b", b"[", b"5~"], false), vec![Key::PageUp]);
    }

    #[test]
    fn a_lone_escape_becomes_esc_only_when_input_goes_idle() {
        assert_eq!(keys(&[b"\x1b"], false), vec![]);
        assert_eq!(keys(&[b"\x1b"], true), vec![Key::Esc]);
    }

    #[test]
    fn background_reply_is_separated_from_typed_keys() {
        assert_eq!(
            keys(&[b"a\x1b]11;rgb:1a1a/1b1b/2626\x07b"], false),
            vec![
                Key::Char('a'),
                Key::Background(0x1a, 0x1b, 0x26),
                Key::Char('b')
            ]
        );
        assert_eq!(
            keys(&[b"\x1b]11;rgb:ff/80/00\x1b\\"], false),
            vec![Key::Background(255, 128, 0)]
        );
    }

    #[test]
    fn control_keys_and_utf8_decode() {
        assert_eq!(
            keys(&[b"\x03\x1a\r\x7f", "설".as_bytes()], false),
            vec![
                Key::Ctrl('c'),
                Key::Ctrl('z'),
                Key::Enter,
                Key::Backspace,
                Key::Char('설')
            ]
        );
    }

    #[test]
    fn unknown_sequences_are_dropped_without_stalling() {
        assert_eq!(keys(&[b"\x1b[200~x"], false), vec![Key::Char('x')]);
        assert_eq!(keys(&[b"\x1b[1"], true), vec![]);
    }
}
