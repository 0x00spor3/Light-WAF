// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Import parser for OWASP CRS / ModSecurity `seclang` rules (B2, `BOUNDARY.md` §1.7).
//!
//! This is the **engine** that lets an operator load their own `SecRule …` files — the
//! *curated premium ruleset content* stays enterprise (`BOUNDARY.md` §2.4). The core ships
//! only the import machinery, never the rules.
//!
//! ## Foundation rule — two channels, never crossed (see the B2 plan, paletto #1)
//! CRS rules declare transformations (`t:lowercase`, `t:urlDecode`, …) that ModSecurity
//! applies to the **raw** request value. Our native modules read the §6 canonical surface
//! (`ctx.normalized.*`), which is ALREADY recursively percent-decoded / NFKC-folded. Feeding
//! that canonical surface into a rule's `t:urlDecode` would double-decode (`%2575`→`%75`→`u`)
//! where ModSecurity decodes once → a silent semantic change (the worst defect in a WAF).
//! Therefore the CRS channel sources values from the **raw** `RequestContext`
//! (`ctx.query`/`ctx.headers`/`ctx.cookies`/`ctx.body`) and the rule's declared `t:`
//! pipeline performs every decode. The native channel is untouched.
//!
//! The 10th hand-rolled parser in this workspace (cf. `graphql_lex`, `grpc_extract`).

pub mod ast;
pub mod lexer;
pub mod module;
pub mod operator;
pub mod parse;
pub mod target;
pub mod transform;

pub use module::CrsModule;
