// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! `seclang` lexer — turns the raw text of a ModSecurity/CRS `.conf` file into a flat
//! list of [`DirectiveLine`]s (directive keyword + raw argument tokens), with the source
//! line number kept for diagnostics. It does NOT interpret the directives (that is
//! [`super::parse`]); it only resolves the *lexical* layer:
//!
//! - **Line continuation** `\` at end of a physical line joins it with the next one.
//! - **Comments**: a `#` as the first non-whitespace char of a logical line starts a
//!   comment to end of line. A `#` inside a quoted string (e.g. a regex `@rx a#b`) is
//!   literal — comments are only recognized at line start, exactly where CRS uses them,
//!   so an unquoted `#` mid-pattern can never accidentally truncate a rule.
//! - **Quoting**: double-quoted tokens may contain spaces; `\"` → `"` and `\\` → `\`,
//!   while any other `\X` is preserved verbatim (so regex escapes like `\d`, `\b`, `\.`
//!   survive — CRS writes them singly, never doubled).
//!
//! Blank/comment logical lines are dropped, so the output is exactly the directive lines.

/// One logical directive line: the directive keyword (`tokens[0]`) plus its raw argument
/// tokens, after continuation-joining and comment stripping. `line_no` is the 1-based
/// physical line where the directive *started* (for boot-time skip/parse diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveLine {
    pub line_no: usize,
    pub tokens: Vec<String>,
}

/// Lex `input` into directive lines. Never panics; malformed quoting is tolerated
/// (an unterminated quote consumes to end of the logical line).
pub fn lex(input: &str) -> Vec<DirectiveLine> {
    let mut out = Vec::new();
    let mut logical = String::new();
    let mut logical_start = 0usize; // 1-based physical line where the logical line began

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        if logical.is_empty() {
            logical_start = line_no;
        }
        // A physical line that ends (after trailing whitespace) with a single `\` is a
        // continuation: drop the backslash and append the next physical line directly
        // (no inserted separator — faithful to ModSecurity, which concatenates and relies
        // on the continuation line's own leading whitespace; CRS always indents them).
        let trimmed_end = raw_line.trim_end();
        if let Some(prefix) = trimmed_end.strip_suffix('\\') {
            logical.push_str(prefix);
            continue;
        }
        logical.push_str(raw_line);

        if let Some(dl) = tokenize_logical(&logical, logical_start) {
            out.push(dl);
        }
        logical.clear();
    }
    // A trailing continuation with no following line: still try to tokenize what we have.
    if !logical.is_empty() {
        if let Some(dl) = tokenize_logical(&logical, logical_start) {
            out.push(dl);
        }
    }
    out
}

/// Tokenize one already-joined logical line. Returns `None` for blank/comment lines.
fn tokenize_logical(line: &str, line_no: usize) -> Option<DirectiveLine> {
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;

    // Skip leading whitespace; a leading `#` (or empty) → comment/blank line.
    while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= n || bytes[i] == b'#' {
        return None;
    }

    let mut tokens: Vec<String> = Vec::new();
    while i < n {
        // Skip inter-token whitespace.
        while i < n && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= n {
            break;
        }
        let mut tok = String::new();
        if bytes[i] == b'"' {
            // Quoted token: spaces allowed; `\"`→`"`, `\\`→`\`, other `\X` verbatim.
            i += 1;
            while i < n {
                let c = bytes[i];
                if c == b'\\' && i + 1 < n {
                    let next = bytes[i + 1];
                    match next {
                        b'"' => {
                            tok.push('"');
                            i += 2;
                        }
                        b'\\' => {
                            tok.push('\\');
                            i += 2;
                        }
                        _ => {
                            // Preserve the backslash AND the next byte (regex escape).
                            tok.push('\\');
                            i += 1;
                        }
                    }
                } else if c == b'"' {
                    i += 1; // closing quote
                    break;
                } else {
                    // Copy one UTF-8 char (push the raw byte run safely).
                    push_byte(&mut tok, line, &mut i);
                }
            }
        } else {
            // Bareword token: up to next whitespace.
            while i < n && bytes[i] != b' ' && bytes[i] != b'\t' {
                push_byte(&mut tok, line, &mut i);
            }
        }
        tokens.push(tok);
    }

    if tokens.is_empty() {
        None
    } else {
        Some(DirectiveLine { line_no, tokens })
    }
}

/// Append the UTF-8 character at byte offset `*i` in `line` to `tok`, advancing `*i`
/// past the whole character. Keeps multibyte sequences intact.
fn push_byte(tok: &mut String, line: &str, i: &mut usize) {
    let rest = &line[*i..];
    if let Some(ch) = rest.chars().next() {
        tok.push(ch);
        *i += ch.len_utf8();
    } else {
        *i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(input: &str) -> Vec<Vec<String>> {
        lex(input).into_iter().map(|d| d.tokens).collect()
    }

    #[test]
    fn simple_secrule_three_tokens() {
        let got = toks(r#"SecRule ARGS "@rx union\s+select" "id:1,phase:2,block""#);
        assert_eq!(
            got,
            vec![vec![
                "SecRule".to_string(),
                "ARGS".to_string(),
                r"@rx union\s+select".to_string(),
                "id:1,phase:2,block".to_string(),
            ]]
        );
    }

    #[test]
    fn regex_backslashes_preserved_singly() {
        // `\d`, `\b`, `\.` must survive verbatim — they are not doubled in CRS files.
        let got = toks(r#"SecRule ARGS "@rx \bunion\b\s\d+\." "id:2""#);
        assert_eq!(got[0][2], r"@rx \bunion\b\s\d+\.");
    }

    #[test]
    fn escaped_quote_inside_string() {
        let got = toks(r#"SecRule ARGS "@rx say \"hi\"" "id:3""#);
        assert_eq!(got[0][2], r#"@rx say "hi""#);
    }

    #[test]
    fn double_backslash_collapses() {
        let got = toks(r#"SecRule ARGS "@rx a\\b" "id:4""#);
        assert_eq!(got[0][2], r"@rx a\b");
    }

    #[test]
    fn line_continuation_joins() {
        let src = "SecRule ARGS \"@rx foo\" \\\n    \"id:5,phase:2,\\\n    block\"";
        let got = toks(src);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0][0], "SecRule");
        assert_eq!(got[0][1], "ARGS");
        assert_eq!(got[0][2], "@rx foo");
        // The action string is joined across the continuation.
        assert_eq!(got[0][3], "id:5,phase:2,    block");
    }

    #[test]
    fn full_line_comment_dropped() {
        let src = "# this is a comment\nSecRule ARGS \"@rx x\" \"id:6\"\n   # indented comment";
        let got = toks(src);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0][3], "id:6");
    }

    #[test]
    fn hash_inside_regex_is_not_a_comment() {
        let got = toks(r##"SecRule ARGS "@rx a#b" "id:7""##);
        assert_eq!(got[0][2], "@rx a#b");
    }

    #[test]
    fn blank_lines_ignored() {
        let src = "\n\n  \nSecRule ARGS \"@rx x\" \"id:8\"\n\n";
        assert_eq!(lex(src).len(), 1);
    }

    #[test]
    fn line_numbers_tracked() {
        let src = "# c\n\nSecRule ARGS \"@rx x\" \"id:9\"";
        let dl = &lex(src)[0];
        assert_eq!(dl.line_no, 3);
    }

    #[test]
    fn pipe_separated_variables_stay_one_token() {
        let got = toks(r#"SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx x" "id:10""#);
        assert_eq!(got[0][1], "ARGS|REQUEST_HEADERS:User-Agent");
    }

    #[test]
    fn secaction_and_unquoted_operator() {
        let got = toks(r#"SecAction "id:900,phase:1,pass,t:none""#);
        assert_eq!(got[0][0], "SecAction");
        assert_eq!(got[0][1], "id:900,phase:1,pass,t:none");
    }
}
