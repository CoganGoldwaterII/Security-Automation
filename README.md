# Security Automation & Engineering Scripts

A collection of security, endpoint-management, and infrastructure automation written in **PowerShell, Python, and Bash**.

The focus is on more than one-off scripts: **reliable workflows that inspect state, make deliberate changes when needed, verify results, and leave useful operational evidence**. Workflows range from endpoint hardening and vulnerability remediation to API integrations, security-platform administration, audit collection, and standalone engineering utilities.

## Repository Structure

Scripts are organized first by **language**, then by **purpose**:

```text
security-automation/
├── powershell/
│   ├── evaluation/
│   ├── remediation/
│   ├── tools/
│   └── Work-In-Progress/
├── python/
│   ├── evaluation/
│   ├── remediation/
│   ├── tools/
│   └── Work-In-Progress/
├── bash/
│   ├── evaluation/
│   ├── remediation/
│   ├── tools/
│   └── Work-In-Progress/
└── README.md
```

| Category | Purpose |
| --- | --- |
| **Evaluation** | Read state, detect drift or risk, and report whether action is needed. |
| **Remediation** | Apply a defined corrective change, with validation and appropriate safeguards. |
| **Tools** | Standalone utilities, API workflows, audit/evidence collectors, reporting, synchronization, and diagnostic scripts that do not fit a paired evaluation/remediation model. |
| **Work-In-Progress** | Scripts actively being developed, revised, or prepared for public release. Move to the appropriate category when ready. |

Rollback scripts live alongside the remediation they reverse and are clearly identified in their filenames. Platform-specific scripts (Windows, Linux, macOS, or cloud/API) are grouped by language rather than a separate OS directory.

*Git does not preserve empty directories. A `.gitkeep` file can hold each category until scripts are added.*

## Automation Model

Many endpoint workflows follow this pattern:

```text
Evaluate → Trigger condition → Remediate → Verify → Log / Report
```

1. **Evaluate:** Inspect the endpoint, platform, or service without changing its configuration.
2. **Decide:** Determine whether action is required based on explicit results.
3. **Remediate:** Apply a targeted, repeatable change only when appropriate.
4. **Verify:** Check that the requested state was achieved rather than assuming a command succeeded.
5. **Record:** Emit useful output and preserve appropriate troubleshooting or audit evidence.

Not every project uses this pipeline. Standalone tools may perform discovery, API operations, reporting, or incident-response evidence collection without an associated remediation script.

### RMM Output Conventions

For **NinjaOne-oriented PowerShell automations**, a common output contract is:

| Script type | Output tokens |
| --- | --- |
| Evaluation | `TRIGGER`, `NO_ACTION`, `ERROR` |
| Remediation | `RESULT`, `NO_ACTION`, `ERROR` |

These workflows commonly terminate with `exit 0`, allowing the automation platform to distinguish outcomes by the output token. A typical remediation condition is **output contains `TRIGGER` and result code `0`**. This convention is specific to those RMM workflows, **not** a universal requirement for every Python, Bash, or standalone tool in this repository.

## Areas of Work

- **Endpoint management:** Application lifecycle, configuration baselines, remote-access software, and Windows hardening.
- **Security operations:** Compliance checks, detection support, security-platform configuration, and vulnerability response.
- **API integrations:** Inventory, reporting, and controlled operations across management and security platforms.
- **Credential and documentation workflows:** Authorized synchronization and validation with scoped access and careful handling of secrets.
- **Audit and incident-response utilities:** Evidence collection, file integrity checks, and operational reporting.
- **Cross-platform automation:** PowerShell, Python, and Bash approaches for different operating systems and execution environments.

Scripts in the main functional directories originated from operational automation work; items in Work-In-Progress may still be under development. Individual file headers and documentation describe the expected environment, prerequisites, inputs, permissions, and intended behavior.

## Engineering Principles

- **Read before writing.** Prefer dedicated, read-only evaluation before making changes when the workflow permits it.
- **Make changes deliberately.** Limit scope and avoid touching healthy or unrelated systems.
- **Design for repeatability.** Use idempotent behavior where practical and treat existing state explicitly.
- **Verify outcomes.** Distinguish an accepted API request or scheduled job from a completed change.
- **Log without leaking.** Preserve useful operational details while excluding passwords, API tokens, secrets, and sensitive evidence.
- **Control privilege.** Use only the access required, protect credential boundaries, and validate target identity and scope.
- **Support recovery.** Provide rollback or recovery guidance for consequential changes where feasible.
- **Handle failure clearly.** Report errors, partial progress, and prerequisites instead of presenting uncertainty as success.

## Using the Scripts

These are **reference implementations and portfolio examples**, not universal drop-in automations.

Before running a script:

1. Review its header, requirements, inputs, target scope, and any destructive operations.
2. Replace generalized configuration values with values appropriate to your environment.
3. Confirm that referenced files, scheduled tasks, APIs, and companion scripts agree on their shared settings.
4. Test in an isolated or otherwise controlled environment and inspect both output and logs.
5. Use a change-control and rollback plan when the operation affects security controls, credentials, networking, or production services.

Some scripts were validated in their original operational environments. **Redacted or generalized publication versions have not necessarily been revalidated after modification.** A successful test of an original script does not automatically validate a sanitized copy.

## About This Repository

This repository documents practical security automation and engineering work across endpoint management, security operations, and integrations. The emphasis is on **clear decision logic, controlled execution, verification, and maintainability**, rather than on language choice alone.

## Disclaimer

Provided for educational, reference, and portfolio purposes. Environment-specific information is intended to be removed or generalized, but users should independently inspect every script before sharing or running it. No script should be executed against systems without authorization. Test and validate all changes before production use.
