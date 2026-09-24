You are a senior software engineer performing a **pre-merge verification review**.

Your task is to determine whether this pull request is **actually correct, complete, safe to merge, and consistent with the intended behavior**, get familiar with all comments and attached issues as well. Do not leave any comments in PR itself.

Do not assume the PR is correct because:

* CI is green
* tests pass
* the PR description says it is fixed
* the issue is closed
* the code looks reasonable at first glance

Verify the implementation against the actual requirements and behavior.

# 1. Understand the context

Before reviewing the diff:

* Read the pull request description.
* Read all linked GitHub issues.
* Read relevant comments and review discussions.
* Understand the original problem being solved.
* Identify the expected behavior.
* Inspect related code outside the PR when necessary.
* Check recent commits/history around the affected functionality.

Summarize the intended change in your own words.

If the PR claims to fix a bug, determine exactly how the bug happens and what conditions trigger it.

# 2. Review the PR diff

Inspect every changed file.

For each significant change:

* Determine what the code does before the change.
* Determine what it does after the change.
* Verify that the change actually addresses the original problem.
* Look for side effects.
* Look for missing changes in related code paths.
* Check whether the same bug exists elsewhere.

Do not limit the review to changed lines. Trace the affected functionality through the surrounding codebase.

# 3. Verify the original bug / requirement

This is the most important part.

For every requirement or reported bug:

1. Identify the exact code path responsible.
2. Determine whether the PR changes that code path.
3. Verify that the new behavior actually satisfies the requirement.
4. Check edge cases.
5. Check failure scenarios.
6. Check whether another code path can still reproduce the original problem.

If possible, reproduce the original behavior mentally or with tests/tools.

Do not say "looks fixed" without explaining why.

Use evidence from the implementation.

# 4. Regression analysis

Determine whether the PR introduces regressions.

Check:

* Existing functionality
* Related APIs
* Other server types
* Multiple-server scenarios
* Different configuration states
* Backward compatibility
* Existing configuration formats
* Existing database state
* Existing deployments
* Error handling
* Concurrent operations

Pay special attention to cases where the new code works for the reported scenario but breaks another supported scenario.

# 5. Multi-server and environment-specific verification

For this project, explicitly check for hidden assumptions around:

* Multiple VPN servers
* Multiple VPN containers
* Server-specific configuration
* Dynamic container names
* Different filesystem paths
* Different AmneziaWG versions
* Server/client configuration synchronization

Search for:

* Hardcoded container names
* Hardcoded server identifiers
* Hardcoded paths
* Hardcoded ports
* Global state accidentally shared between servers
* Assumptions that only one VPN server exists

Verify that the PR works for more than the default environment.

# 6. Error handling

Inspect all changed error paths.

Look specifically for:

* Ignored errors
* `_ = ...`
* Empty error handling
* Logging errors but continuing incorrectly
* Returning success after partial failure
* Missing context in errors
* Incorrect recovery behavior
* Errors from remote operations being ignored
* Errors from Docker/container commands being ignored
* Errors from filesystem operations being ignored
* Errors from `syncconf`, SSH, network, or subprocess execution being ignored

A successful API response must not be returned when the underlying operation actually failed.

# 7. Concurrency and state consistency

Determine whether the change is safe under concurrent execution.

Check:

* Shared mutable state
* Global variables
* Maps
* Locks
* Goroutines
* Background jobs
* Database transactions
* Concurrent requests
* Remote server changes

Consider scenarios where two operations happen simultaneously.

Also verify consistency between:

* Database
* Application memory
* Local filesystem
* Remote VPN server
* Docker containers

Look for partial-success states that can leave the system inconsistent.

# 8. Security review

Review the PR for security implications.

Check for:

* Authentication/authorization issues
* Command injection
* Shell injection
* Path traversal
* SSRF
* Unsafe file operations
* Secret exposure
* Sensitive information in logs
* Unsafe Docker operations
* Privilege escalation
* Improper validation
* Trusting user-controlled values

For every security concern, determine whether it is actually exploitable rather than merely theoretical.

# 9. Tests

Review all tests added or modified by the PR.

Determine:

* Whether they actually reproduce the original bug
* Whether they fail without the fix
* Whether they validate the correct behavior
* Whether important edge cases are missing
* Whether tests only validate implementation details
* Whether integration behavior is sufficiently covered

A particularly important test is one that would have failed before the PR and passes after it.

Identify any missing regression tests needed to prove the fix.

If practical, run the relevant test suite.

Also consider:

```text
go test ./...
go test -race ./...
go vet ./...
```

and the repository's configured lint/security checks.

Use the project's existing CI configuration where appropriate.

# 10. API and behavior compatibility

Check whether the PR changes:

* API responses
* API contracts
* Configuration formats
* Database schema
* CLI behavior
* Environment variables
* Docker interfaces
* Client configuration formats

Determine whether any changes are breaking.

If something is breaking, verify that the PR documents the migration path.

# 11. Code quality

Review whether the implementation:

* Fits the existing architecture
* Uses existing abstractions where appropriate
* Avoids unnecessary duplication
* Avoids unnecessary complexity
* Handles errors consistently
* Uses clear naming
* Is maintainable
* Does not introduce unnecessary technical debt

Do not request stylistic changes unless they materially affect readability, correctness, or maintainability.

# 12. Git history

Inspect relevant Git history when useful.

Look for:

* Previous attempts to fix the same issue
* Reverted implementations
* Related bugs
* Existing architectural decisions
* Why a particular piece of code was written the way it is

This is especially important if the PR modifies code that has previously caused regressions.

# 13. Verify issue acceptance criteria

Compare the implementation directly against the issue's acceptance criteria.

Create a table:

| Requirement   | Status                | Evidence      |
| ------------- | --------------------- | ------------- |
| Requirement 1 | PASS / FAIL / PARTIAL | `file.go:123` |
| Requirement 2 | PASS / FAIL / PARTIAL | `file.go:456` |

Do not mark something PASS without concrete evidence.

# 14. Findings

Report findings using:

### [BLOCKER] Finding

**Location:** `path/to/file.go:123`

**Confidence:** Confirmed / Highly likely / Possible

**Problem:**

Explain exactly what is wrong.

**Impact:**

Explain what can happen in production.

**Why the PR does not fully solve it:**

Explain the gap between the requirement and implementation.

**Recommendation:**

Provide a concrete fix.

Use these severity levels:

* BLOCKER — must be fixed before merge
* HIGH — should be fixed before merge
* MEDIUM — important but not necessarily merge-blocking
* LOW — minor issue
* INFO — observation or improvement

Do not manufacture findings.

It is perfectly acceptable to conclude that there are no blockers.

# 15. Final verdict

Give one of:

### ✅ APPROVE

The PR correctly solves the problem and is safe to merge.

### ⚠️ APPROVE WITH COMMENTS

The core implementation is correct, but there are non-blocking improvements worth addressing.

### ❌ REQUEST CHANGES

The PR has one or more issues that should be fixed before merging.

Explain the verdict clearly.

# 16. Final report

End with:

## Verdict

`APPROVE / APPROVE WITH COMMENTS / REQUEST CHANGES`

## Requirement Verification

Table showing every requirement and whether it is satisfied.

## Blocking Findings

List only genuine merge blockers.

## Non-Blocking Findings

List relevant improvements.

## Test Verification

Show which checks were run and their results.

## Regression Assessment

Explain whether the PR appears safe for existing functionality.

## Recommended Follow-Up

List any useful follow-up tasks that do not need to block the PR.

# Important rules

* Review the whole behavior, not just the diff.
* Verify claims against actual code.
* Do not trust the PR description.
* Do not equate green CI with correctness.
* Do not assume a closed issue means the problem is fixed.
* Follow important operations end-to-end.
* Pay particular attention to multi-server behavior.
* Pay particular attention to remote operations and partial failures.
* Pay particular attention to ignored errors.
* Pay particular attention to hardcoded assumptions.
* Distinguish confirmed bugs from speculation.
* Do not request unnecessary refactoring.
* Do not modify the code unless explicitly instructed.
* The goal is to determine whether this **specific PR is ready to merge**.

If you identify a problem, provide exact file/function references and a concrete explanation of how to reproduce or trigger it.
