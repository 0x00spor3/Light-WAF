// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! `waf-license-sign` — issue a signed `license.json` for a demo.
//!
//! Reads the private seed from `WAF_LICENSE_SIGNING_KEY` (hex, from `waf-license-keygen`) and writes
//! a signed license valid for `--days` from now.
//!
//! ```text
//! WAF_LICENSE_SIGNING_KEY=<seed-hex> \
//!   waf-license-sign --issued-to "Acme Corp — POC" --days 30 --out license.json
//! ```

use time::OffsetDateTime;

fn main() {
    if let Err(err) = run() {
        eprintln!("waf-license-sign: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let seed = std::env::var("WAF_LICENSE_SIGNING_KEY")
        .map_err(|_| "set WAF_LICENSE_SIGNING_KEY to the hex signing seed".to_string())?;

    let mut issued_to: Option<String> = None;
    let mut days: i64 = 30;
    let mut edition = "demo".to_string();
    let mut out = "license.json".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--issued-to" => issued_to = Some(args.next().ok_or("--issued-to NAME")?),
            "--days" => {
                days = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--days N (integer)")?
            }
            "--edition" => edition = args.next().ok_or("--edition NAME")?,
            "--out" => out = args.next().ok_or("--out PATH")?,
            "-h" | "--help" => {
                println!(
                    "usage: waf-license-sign --issued-to NAME [--days N] [--edition E] [--out PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let issued_to = issued_to.ok_or("--issued-to NAME is required")?;
    let issued_at = OffsetDateTime::now_utc();
    let expires_at = issued_at + time::Duration::days(days);

    let bytes = waf_license::sign_license(
        &edition,
        &issued_to,
        issued_at,
        expires_at,
        vec!["*".to_string()],
        &seed,
    )
    .map_err(|e| e.to_string())?;

    std::fs::write(&out, &bytes).map_err(|e| format!("writing {out}: {e}"))?;
    println!("wrote {out}: edition={edition} issued_to={issued_to:?} expires_at={expires_at}");
    Ok(())
}
