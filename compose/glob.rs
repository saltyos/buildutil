//! SPDX-License-Identifier: GPL-2.0-only
//! buildutil-compose — neutral stage-relative glob matching

/// Stage-relative glob: `*` stops at `/`, `**` crosses it, a trailing `/`
/// means "this directory and everything under it".
pub fn glob_match(pat: &str, s: &str) -> bool {
    let (body, dir_only) = if let Some(stripped) = pat.strip_suffix('/') {
        (stripped, true)
    } else {
        (pat, false)
    };
    if dir_only {
        return s == body || s.starts_with(&format!("{}/", body));
    }
    let p: Vec<char> = body.chars().collect();
    let t: Vec<char> = s.chars().collect();
    glob_rec(&p, 0, &t, 0)
}

fn glob_rec(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    loop {
        if pi >= p.len() {
            return ti >= t.len();
        }
        if p[pi] == '*' {
            let double = pi + 1 < p.len() && p[pi + 1] == '*';
            pi += if double { 2 } else { 1 };
            if pi >= p.len() && double {
                return true;
            }
            let mut k = ti;
            loop {
                if glob_rec(p, pi, t, k) {
                    return true;
                }
                if k >= t.len() {
                    return false;
                }
                if !double && t[k] == '/' {
                    return false;
                }
                k += 1;
            }
        }
        if ti >= t.len() {
            return false;
        }
        if p[pi] != '?' && p[pi] != t[ti] {
            return false;
        }
        pi += 1;
        ti += 1;
    }
}
