# Revised Task P Changes

## Reviewer Feedback Addressed

### 1. Timeout Handling

* Replaced `timedelta.seconds` with `total_seconds()`
* Added multi-day stale gate timeout test

### 2. Replay Protection

* Signatures now bind:

  * action identity
  * approver identity
  * credential class
  * issued-at timestamp
* Added replay attack rejection tests
* Added stale approval rejection tests

### 3. Closed Credential Enumeration

* Replaced free-form credential strings with `CredentialClass` enum
* Added four credential classes:

  * ENGINEER
  * SECURITY
  * OPERATIONS
  * COMPLIANCE

### 4. Immutable Audit Logging

* Audit log converted to append-only tuple storage
* Added immutable audit-log validation tests
* Added audit query accessor

### 5. Contract Alignment

* Added:

  * `GateHandle`
  * `GateDecision`
  * `check(handle)`
  * `open_gate(action, policy)`
  * `submit_approval -> GateState`
* Added configurable timeout handler stub

### 6. Expanded Test Coverage

* Expanded suite to 22 automated tests
* Added adversarial attack coverage
* Added replay, timeout-race, tampering, and stale approval tests


