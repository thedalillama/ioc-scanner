# Handoff Guidance

This document is for any agent taking over work in this repository or a similar operational codebase. It captures the process lessons from this session in generalized form.

## Core Rule

Use this loop for any bug fix, behavior change, deployment change, or operational claim:

1. Reproduce
2. Fix
3. Verify
4. Notify

Do not skip the verification step. Do not announce completion based only on code inspection.

## Fix-Verify-Notify Loop

### 1. Reproduce

Before changing code:

- identify the exact failing behavior
- capture the concrete input, environment, and expected output
- reduce the problem to the smallest reproducible case

Examples:

- a specific timestamp string that renders incorrectly
- a specific scheduled task action that returns access denied
- a specific installer path that fails on a clean VM

If reproduction is unclear, do not guess. Narrow it first.

### 2. Fix

Apply the smallest change that addresses the reproduced failure.

Avoid mixing:

- bug fix
- refactor
- cleanup
- product redesign

in one step unless they are tightly coupled.

### 3. Verify

Verification is required before reporting success.

Choose the strongest available verification method:

1. direct runtime behavior
2. live served output
3. automated tests
4. code-path inspection

Use more than one when the change is high-risk.

Examples:

- for UI rendering:
  - verify the live HTML being served
  - if possible, verify visually in a browser
- for scheduled tasks:
  - verify actual task state and actual action behavior
- for installer changes:
  - verify on a clean target, not just in the dev workspace
- for parsers/formatters:
  - test the exact failing input string

If verification fails, the fix is not done.

### 4. Notify

Only after verification succeeds:

- state what changed
- state how it was verified
- state any remaining limitations clearly

Do not say “fixed” when the change is only plausible.

## Verification Standards

### Prefer Real Outputs Over Assumptions

Code that looks correct is not enough.

Use:

- actual command output
- actual files written
- actual task state
- actual HTTP responses
- actual rendered HTML
- actual runtime logs

instead of inferred correctness.

### Verify the Exact Input Shape

A common failure pattern is fixing a nearby case but not the real one.

Example pattern:

- timestamp parser handles normal ISO strings
- production data includes 7-digit fractional seconds
- untested parser falls back to raw text

So when a user reports a failure:

- test the exact reported value or a faithful copy

not just a simplified equivalent.

### Read What the System Is Actually Serving

For web/UI work, verify the live server output when possible.

Useful checks:

- fetch the live page or API response
- inspect the exact HTML or JSON being served
- confirm the specific field or card markup changed

This is especially useful when browser screenshot tooling is unavailable.

### Distinguish “Server Correct” From “Browser Correct”

If the live HTML is correct but the user still sees old behavior, suspect:

- stale server process
- stale browser tab
- cached content
- multiple listeners on different ports

Do not assume the code change failed until you rule out stale runtime state.

## Process Hygiene

### Avoid Stale Runtime Instances

Operational tooling often fails because an older process is still serving requests.

When restarting local services:

- identify all matching processes
- stop old instances explicitly
- restart one clean instance
- verify which PID/port is live

If the launcher is under your control, make it replace stale instances automatically.

### Prefer Deterministic Launch Paths

If a scheduled task or helper path is brittle:

- shorten command lines
- reduce nested quoting
- prefer launcher scripts over long inline commands

This reduces ambiguity and makes runtime diagnosis easier.

### Keep Dev, Runtime, and Test Environments Separate

Use separate roles:

- dev workspace
- deployed runtime
- mutable runtime data
- clean test environment or VM

Do not mix source, reports, and runtime state unnecessarily.

### Clean Before Commit

Before packaging for Git:

- remove generated reports
- remove screenshots and scratch files
- remove temporary deployment directories
- ignore runtime byproducts

Then confirm:

- intended source files are staged
- working tree is clean after commit

## Testing Strategy

Use layered testing:

### Unit Tests

Use for:

- parsing
- formatting
- normalization
- small state transitions

These are cheap and should cover exact edge cases that previously failed.

### Smoke Tests

Use for:

- script parse checks
- basic module execution
- test suite invocation

These confirm the repo is runnable after changes.

### Runtime Tests

Use for:

- scheduled task behavior
- alert flow
- installer flow
- live UI behavior

These catch the issues unit tests miss.

### Clean-Machine Tests

Use a VM or separate runtime when validating:

- installers
- prerequisites
- first-run experience
- task registration

A dev machine is not evidence of clean install success.

## When the User Reports a Bug

Treat the report as truth about observed behavior until disproven.

Do not respond with:

- “it should work”
- “the code looks right”
- “that is expected”

unless you have already verified the actual live behavior.

Better sequence:

1. capture the reported symptom
2. inspect the live behavior
3. reproduce locally if possible
4. patch
5. verify the exact symptom is gone

## Communicating Progress

While working:

- say what you are checking
- say what you learned
- distinguish observation from inference

When done:

- report what changed
- report how it was verified
- report any known residual risk

Example:

- bad: “Fixed.”
- better: “Changed the timestamp renderer, then verified the live page HTML now serves date and time on separate lines for the exact failing timestamp shape.”

## What to Do When Tooling Is Limited

If one verification path is unavailable:

- choose the strongest remaining path
- state the limitation explicitly

Examples:

- if browser screenshot tooling is unavailable:
  - inspect live rendered HTML
- if direct visual access is unavailable:
  - inspect exact response payloads and runtime outputs
- if external network is blocked:
  - verify local state and local behavior directly

But do not silently downgrade verification quality. Say what was and was not verified.

## Operational Lessons From This Project

These patterns are broadly useful:

- task schedulers can report success while the underlying UX still fails
- popup/notification flows often fail because of launch context, not business logic
- local state and live output can drift apart when multiple instances are running
- integer size assumptions can break status collection on Windows result codes
- path, quoting, and launch indirection matter as much as script logic

So for systems work:

- verify the actual runtime context
- verify the exact output surface
- verify the exact data shape

## Completion Standard

A change is complete only when:

- the issue is reproduced or otherwise concretely identified
- the code is updated
- the relevant verification passes
- the user is informed of both the fix and the verification method

If any one of those is missing, the work is not complete.
