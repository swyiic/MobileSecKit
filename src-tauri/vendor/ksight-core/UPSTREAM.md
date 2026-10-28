Vendored from https://github.com/swyiic/KernSight at v0.2.10
(commit 6b0a244fb99ed738894dd48d4058356d4a3e7302).

The production change bounds stitched report previews before appending and respects UTF-8 boundaries. Regression tests cover Chinese, accented characters, emoji, and the URL separator.
The manifest resolves upstream workspace dependencies explicitly; native_frameworks.json is retained unchanged with its include path relocated.
Keep this patch until the Git dependency is upgraded to a release containing the fix. The Cargo cache is never modified.
