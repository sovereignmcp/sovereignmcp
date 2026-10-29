# Security policy

SovereignMCP is a security tool, so reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting: the **Security** tab, then **Report a vulnerability**.
Include what you found, how to reproduce it, and the impact. A proof of concept helps.

We aim to acknowledge reports within a few days and to keep you updated. We will credit you if you want credit.

## Scope

In scope: bypasses of the Intersection Rule, argument/SQL/command/URL inspection bypasses, approval bypasses (including self-approval,
replay, wrong approver), audit-log tampering that goes undetected, signature/verification flaws in cloud mode, and secret leakage.

Known limits (see the README) are documented, not vulnerabilities: shell inspection is risk reduction, DNS rebinding and redirects are the fetcher's job,
and the audit log is tamper-evident rather than immutable.

## Good-faith research

If you act in good faith, stay within your own test setup, do not access other people's data, and give us reasonable time to fix an issue
before disclosing it, we will not pursue action against you.
