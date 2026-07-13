//! Human-readable table rendering of the shared check results.

use std::fmt::Write as _;

use foreign_chain_health_check::{ProviderResult, Status};

/// Whether any provider check failed (skips do not count as failures).
pub fn any_failed(results: &[ProviderResult]) -> bool {
    results
        .iter()
        .any(|r| matches!(r.status, Status::Failed(_)))
}

/// Render an aligned table and summary. Failure reasons are listed below the
/// table (not in the `RESULT` column) so a long or multi-line error can't break
/// the alignment.
pub fn render(results: &[ProviderResult]) -> String {
    let chain_w = results
        .iter()
        .map(|r| r.chain.len())
        .max()
        .unwrap_or(0)
        .max("CHAIN".len());
    let provider_w = results
        .iter()
        .map(|r| r.provider.len())
        .max()
        .unwrap_or(0)
        .max("PROVIDER".len());

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<chain_w$}  {:<provider_w$}  RESULT",
        "CHAIN", "PROVIDER",
    );

    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    for r in results {
        let result = match &r.status {
            Status::Passed => {
                passed += 1;
                "✓ ok".to_string()
            }
            Status::Failed(_) => {
                failed += 1;
                "✗ failed".to_string()
            }
            Status::Skipped(reason) => {
                skipped += 1;
                format!("– skipped ({reason})")
            }
        };
        let _ = writeln!(
            out,
            "{:<chain_w$}  {:<provider_w$}  {result}",
            r.chain, r.provider,
        );
    }

    let _ = writeln!(out, "\n{passed} passed, {failed} failed, {skipped} skipped");

    if failed > 0 {
        let _ = writeln!(out, "\nFailures:");
        for r in results {
            if let Status::Failed(reason) = &r.status {
                let _ = writeln!(out, "  {} / {}: {reason}", r.chain, r.provider);
            }
        }
    }

    out
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn any_failed__should_ignore_skips_and_passes() {
        // Given
        let results = vec![
            ProviderResult {
                chain: "base",
                provider: "a".to_string(),
                status: Status::Passed,
            },
            ProviderResult::skipped("ethereum", "b".to_string(), "unsupported"),
        ];

        // When / Then
        assert!(!(any_failed(&results)));
    }

    #[test]
    fn any_failed__should_detect_a_failure() {
        // Given
        let results = vec![ProviderResult {
            chain: "base",
            provider: "a".to_string(),
            status: Status::Failed("boom".to_string()),
        }];

        // When / Then
        assert!(any_failed(&results));
    }

    #[test]
    fn render__should_include_chain_provider_and_reason() {
        // Given
        let results = vec![ProviderResult {
            chain: "base",
            provider: "alchemy".to_string(),
            status: Status::Failed("bad url".to_string()),
        }];

        // When
        let table = render(&results);

        // Then
        assert!(table.contains("base"));
        assert!(table.contains("alchemy"));
        assert!(table.contains("bad url"));
        assert!(table.contains("0 passed, 1 failed, 0 skipped"));
    }
}
