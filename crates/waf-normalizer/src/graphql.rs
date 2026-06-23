//! Minimal GraphQL lexer (Phase 11) — the 8th custom parser in this crate (fuzzed,
//! see ARCHITECTURE §13). It does NOT build an AST: it makes a single linear,
//! UTF-8-safe, allocation-free pass over the query text and computes the structural
//! metrics the `graphql` detection module enforces (depth / aliases / fields /
//! directives / introspection). It is evasion-robust at the LEXICAL level — braces,
//! colons and names inside strings, block strings (`"""…"""`) and `#` comments are
//! skipped, so they cannot inflate or deflate the counts.
//!
//! **Paren-aware depth.** `{ }` delimits a *selection set* (which is what "depth"
//! means for a GraphQL DoS) but ALSO an *input object* inside an argument list
//! (`field(arg: { … })`). To count only selection-set nesting, a `{` increments the
//! depth ONLY while not inside `(` … `)`. So a query with a deeply nested input
//! object but a flat selection set reports a *small* depth (no false positive).

/// Structural metrics of one GraphQL query/operation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GraphqlStats {
    /// Maximum selection-set nesting depth (paren-aware: input-object braces excluded).
    pub max_depth: u32,
    /// Alias separators (`alias: field`) — a `:` in selection-set context. The
    /// "alias bomb" DoS signal.
    pub aliases: u32,
    /// Field/selection name tokens in selection-set context. A cheap complexity proxy.
    pub fields: u32,
    /// `@directive` occurrences.
    pub directives: u32,
    /// A schema-introspection meta-field (`__schema` / `__type`) is present. NB:
    /// `__typename` is deliberately NOT counted (it is benign and ubiquitous).
    pub has_introspection: bool,
}

/// Lex `s` and compute its [`GraphqlStats`]. Linear time, no allocation, never panics.
pub fn graphql_lex(s: &str) -> GraphqlStats {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;

    let mut depth: u32 = 0;
    let mut paren: u32 = 0;
    let mut st = GraphqlStats::default();

    while i < n {
        let c = b[i];
        match c {
            // `#` line comment → skip to end of line.
            b'#' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            // Block string `"""…"""` (may contain `"` and newlines; `\` escapes).
            b'"' if i + 2 < n && b[i + 1] == b'"' && b[i + 2] == b'"' => {
                i += 3;
                while i + 2 < n && !(b[i] == b'"' && b[i + 1] == b'"' && b[i + 2] == b'"') {
                    if b[i] == b'\\' {
                        i += 1; // skip the escaped byte (incl. an escaped `"""`)
                    }
                    i += 1;
                }
                i = (i + 3).min(n); // past the closing `"""` (or clamp at EOF)
            }
            // Normal string `"…"` (`\` escapes the next byte). A `"` byte never occurs
            // inside a UTF-8 multibyte sequence, so scanning bytes is safe.
            b'"' => {
                i += 1;
                while i < n && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // past the closing quote (or EOF)
            }
            b'(' => {
                paren += 1;
                i += 1;
            }
            b')' => {
                paren = paren.saturating_sub(1);
                i += 1;
            }
            b'{' => {
                if paren == 0 {
                    depth += 1;
                    if depth > st.max_depth {
                        st.max_depth = depth;
                    }
                }
                i += 1;
            }
            b'}' => {
                if paren == 0 {
                    depth = depth.saturating_sub(1);
                }
                i += 1;
            }
            // In a selection set the only `:` is an alias separator; argument `:` lives
            // inside `(` … `)` and is excluded.
            b':' if paren == 0 => {
                st.aliases += 1;
                i += 1;
            }
            b'@' => {
                st.directives += 1;
                i += 1;
            }
            // Name: [_A-Za-z][_0-9A-Za-z]* — counted only as a selection (paren==0, depth>0).
            _ if c == b'_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < n && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                if paren == 0 && depth > 0 {
                    st.fields += 1;
                    let name = &b[start..i];
                    if name == b"__schema" || name == b"__type" {
                        st.has_introspection = true;
                    }
                }
            }
            // Whitespace, commas, `$ = ! [ ] . | &` and any other byte: insignificant.
            _ => {
                i += 1;
            }
        }
    }

    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_query_depth_and_fields() {
        let st = graphql_lex("query { user { id name } }");
        assert_eq!(st.max_depth, 2); // user { … } inside the outer selection set
        assert_eq!(st.fields, 3); // user, id, name
        assert_eq!(st.aliases, 0);
        assert!(!st.has_introspection);
    }

    #[test]
    fn paren_aware_trap_flat_selection_deep_input_object() {
        // The Phase-11 Step-0 trap: a deeply nested input OBJECT in an argument, but a
        // FLAT selection set. Depth must be 2 (mutation { c { id } }), NOT ~6.
        let st = graphql_lex("mutation{c(input:{a:{b:{c:{d:1}}}}){id}}");
        assert_eq!(st.max_depth, 2);
    }

    #[test]
    fn deep_nesting() {
        let mut q = String::from("query");
        for _ in 0..20 {
            q.push_str("{a");
        }
        q.push_str("{id}");
        for _ in 0..21 {
            q.push('}');
        }
        assert_eq!(graphql_lex(&q).max_depth, 21);
    }

    #[test]
    fn alias_bomb() {
        let st = graphql_lex("query{a:f b:f c:f d:f}");
        assert_eq!(st.aliases, 4);
    }

    #[test]
    fn introspection_detected() {
        assert!(graphql_lex("query{__schema{types{name}}}").has_introspection);
        assert!(graphql_lex("{__type(name:\"X\"){fields{name}}}").has_introspection);
    }

    #[test]
    fn typename_is_not_introspection() {
        assert!(!graphql_lex("query{user{__typename id}}").has_introspection);
    }

    #[test]
    fn directives_counted() {
        let st = graphql_lex("query{field @include(if:true) other @skip(if:false)}");
        assert_eq!(st.directives, 2);
    }

    #[test]
    fn braces_in_string_do_not_count() {
        // The `}}}}` inside the string must not close the selection set.
        let st = graphql_lex(r#"{a(x:"}}}}}}")b}"#);
        assert_eq!(st.max_depth, 1);
    }

    #[test]
    fn braces_in_comment_do_not_count() {
        let st = graphql_lex("{a # }}}} not real\n b}");
        assert_eq!(st.max_depth, 1);
    }

    #[test]
    fn braces_in_block_string_do_not_count() {
        let st = graphql_lex(r#"{a(x:"""}}} still a string """)b}"#);
        assert_eq!(st.max_depth, 1);
    }

    #[test]
    fn unterminated_string_and_braces_terminate() {
        // Must not hang / panic on malformed input.
        let _ = graphql_lex("query{a(x:\"unterminated");
        let _ = graphql_lex("{{{{{{{{");
        let _ = graphql_lex("\"\"\"unterminated block");
        let _ = graphql_lex("");
    }
}
