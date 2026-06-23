// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! JSON flatten robustness — Fase 8, target DEC 2 #5 (`flatten_value`/`flatten_json`:
//! depth-limited RECURSION over an already-parsed `serde_json::Value`).
//!
//! The risk here is recursion, not parsing (the parse is serde_json's, robust). So we
//! build `Value`s DIRECTLY (bypassing serde's parse-depth cap) and check:
//!   (1) non-panic on arbitrary Value;
//!   (2) the depth limit fires with `Err(JsonDepthExceeded)` BEFORE the recursion
//!       blows the stack, AND at the right point (off-by-one in the guard would show
//!       here). Exercised at MODERATE over-limit depth so the bug is observable as a
//!       wrong return value (Ok where Err is due) rather than a SIGSEGV;
//!   (3) width is bounded: #pairs == #leaves exactly (one pair per scalar/null leaf),
//!       so a giant flat array cannot explode beyond its leaf count.
//!
//! Caveat (2b): a bite that DISABLES the depth guard, exercised at EXTREME depth,
//! would stack-overflow → SIGSEGV (a process crash proptest cannot catch as a clean
//! failure). We therefore bite at moderate depth, where the divergence is a wrong
//! Ok/Err *before* any overflow — the real proof the guard fires at the right point.

use proptest::prelude::*;
use serde_json::Value;
use waf_core::LimitsConfig;
use waf_normalizer::body::flatten_value;
use waf_normalizer::NormalizationError;

fn limits_depth(max_json_depth: usize) -> LimitsConfig {
    LimitsConfig { max_json_depth, ..LimitsConfig::default() }
}

/// `depth` nested arrays wrapping a Null leaf. flatten_json checks at depths 1..=depth
/// → errors iff `depth > max_json_depth`.
fn nest(depth: usize) -> Value {
    let mut v = Value::Null;
    for _ in 0..depth {
        v = Value::Array(vec![v]);
    }
    v
}

/// Independent leaf count: one per scalar/string/null; objects/arrays recurse.
fn count_leaves(v: &Value) -> usize {
    match v {
        Value::Object(m) => m.values().map(count_leaves).sum(),
        Value::Array(a) => a.iter().map(count_leaves).sum(),
        _ => 1,
    }
}

// ── (2) the depth guard fires at the right point, before any overflow ─────────

#[test]
fn depth_limit_fires_at_the_right_point() {
    // Moderate depths only (no overflow): the guard must turn d > m into an error
    // and leave d <= m as Ok — an off-by-one or a disabled guard shows up here.
    for m in 1..=8 {
        let lim = limits_depth(m);
        for d in 0..=(m + 3) {
            let res = flatten_value(&nest(d), &lim);
            if d > m {
                assert!(
                    matches!(res, Err(NormalizationError::JsonDepthExceeded { .. })),
                    "depth {d} > max {m} must error, got {res:?}"
                );
            } else {
                assert!(res.is_ok(), "depth {d} <= max {m} must be ok, got {res:?}");
            }
        }
    }
}

// ── (1)+(3) non-panic and exact leaf-count on arbitrary Values ────────────────

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(n.into())),
        "[a-z0-9]{0,8}".prop_map(Value::String),
    ];
    // up to ~6 levels deep, ~64 nodes, ~8 children per collection.
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::hash_map("[a-z]{1,4}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn prop_flatten_non_panic_and_leaf_count(v in arb_json()) {
        // Default depth (20) > the generated depth (~6) → always Ok here.
        let pairs = flatten_value(&v, &LimitsConfig::default()).expect("within depth");
        // (3) width bound: exactly one pair per leaf, never an explosion.
        prop_assert_eq!(pairs.len(), count_leaves(&v));
    }
}

#[test]
fn flat_giant_array_is_bounded_by_leaf_count() {
    // (3) A huge SHALLOW array passes the depth check but must still yield exactly
    // one pair per element — bounded by the leaf count, not unbounded.
    let arr = Value::Array((0..10_000).map(Value::from).collect());
    let pairs = flatten_value(&arr, &LimitsConfig::default()).unwrap();
    assert_eq!(pairs.len(), 10_000);
}
