Analyze this pull request focusing on CRITICAL issues only. Be concise and actionable.

**IMPORTANT - CONTEXT AWARENESS:**
- Review any existing PR comments and discussions provided alongside this prompt before giving feedback
- Do not duplicate points already raised in existing discussions
- If a resolved thread addressed an issue, do not re-raise it

PRIORITY CHECKS (report only if found):

1. Logic & Correctness
   - Logic flaws or incorrect implementations
   - Missing edge cases (empty inputs, boundary conditions, None/Some variants)
   - Unhandled error paths or panics in production code
   - Backward compatibility issues with existing APIs/data formats

2. Project Engineering Standards
   - Enforce all standards defined in [CONTRIBUTING.md] (don't panic, local reasonability, safe arithmetic, separate business logic from I/O, tests required, etc.)

3. Production Safety
   - Breaking changes that could fail during rolling updates
   - State migration issues between old/new versions
   - Race conditions or data consistency problems
   - Resource leaks (memory, file handles, connections)

4. Performance
   - Blocking operations in async functions (sync I/O, CPU-intensive work)
   - Unnecessary allocations or excessive `.clone()` calls (suggest borrows/references)
   - Sequential operations that should be parallel (tokio::join!/select!)
   - Missing timeouts on external calls

5. Rust-Specific Concerns
   - Unsafe code without safety comments explaining invariants
   - Incorrect ownership patterns or lifetime issues
   - Concurrency issues (Arc/Mutex misuse, data races)

6. Code Quality
   - Poor modularity (functions >100 lines, god objects)
   - Violated Single Responsibility Principle
   - Security vulnerabilities (injection, hardcoded secrets)

REVIEW STYLE:
- List only issues that should block the merge
- Use bullet points, be direct and specific
- Provide code suggestions for fixes when helpful
- Do NOT comment on style, formatting, naming, or documentation unless it causes a bug
- Do NOT restate what the diff already shows
- If no critical issues found: approve with a one-line summary
- Sign off with: ✅ (approved) or ⚠️ (issues found)

Consult the repository's [CLAUDE.md], [CONTRIBUTING.md], and [AGENTS.md] for project-specific conventions.
Don't try to use `gh pr review` you don't have permissions for that and it will fail. 
Please always use `gh pr comment` to post your review instead.

[CLAUDE.md]: ../../CLAUDE.md
[CONTRIBUTING.md]: ../../CONTRIBUTING.md
[AGENTS.md]: ../../AGENTS.md
