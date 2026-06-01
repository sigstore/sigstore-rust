//! Minimal Unix shell-style wildcard matching for TUF delegation paths.
//!
//! TUF delegation `paths` use shell-style globs (Python's `fnmatch`). This
//! implements the subset that real-world Sigstore/`tuf-on-ci` repositories use:
//! `*` (matches any run of characters, including `/`) and `?` (matches exactly
//! one character). Character classes (`[...]`) are treated as literals; if a
//! repository ever needs them this matcher should be extended.

/// Return whether `text` matches the shell-style `pattern`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    // Classic two-pointer wildcard match with backtracking on `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            // Backtrack: let the last `*` swallow one more character.
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }

    // Consume any trailing `*`s in the pattern.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn matches_literals_and_wildcards() {
        assert!(glob_match("trusted_root.json", "trusted_root.json"));
        assert!(!glob_match("trusted_root.json", "signing_config.json"));
        assert!(glob_match("*.json", "trusted_root.json"));
        assert!(glob_match("registry/*", "registry/index.json"));
        assert!(glob_match("*", "anything/at/all"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("foo*bar", "fooXYZbar"));
        assert!(!glob_match("foo*bar", "fooXYZbaz"));
    }
}
