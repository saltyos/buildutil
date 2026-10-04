//! SPDX-License-Identifier: GPL-2.0-only
//! Engine-core stage-relative glob matching.

/// `*` stops at `/`, `**` crosses it, and a trailing `/` covers descendants.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let (body, dir_only) = pattern
        .strip_suffix('/')
        .map_or((pattern, false), |body| (body, true));
    if dir_only {
        return value == body || value.starts_with(&format!("{body}/"));
    }
    let pattern: Vec<char> = body.chars().collect();
    let value: Vec<char> = value.chars().collect();
    glob_rec(&pattern, 0, &value, 0)
}

fn glob_rec(pattern: &[char], mut pi: usize, value: &[char], mut vi: usize) -> bool {
    loop {
        if pi == pattern.len() {
            return vi == value.len();
        }
        if pattern[pi] == '*' {
            let double = pi + 1 < pattern.len() && pattern[pi + 1] == '*';
            pi += if double { 2 } else { 1 };
            if pi == pattern.len() && double {
                return true;
            }
            loop {
                if glob_rec(pattern, pi, value, vi) {
                    return true;
                }
                if vi == value.len() || (!double && value[vi] == '/') {
                    return false;
                }
                vi += 1;
            }
        }
        if vi == value.len() || (pattern[pi] != '?' && pattern[pi] != value[vi]) {
            return false;
        }
        pi += 1;
        vi += 1;
    }
}
