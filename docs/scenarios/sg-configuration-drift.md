# Security Group Configuration Drift

## Objective

Validate whether administrative SSH access complies with the lab security
baseline, identify unauthorized configuration changes, and verify remediation.

## Security Baseline

NET-01:
SSH administrative access must be restricted to the approved administrator CIDR.

## Test Safety

The test security group was not attached to any EC2 instance.
Therefore, the insecure rule was reproduced without exposing the running workload.

## Normal State

TCP/22 → <APPROVED_ADMIN_CIDR>/32

Baseline checker result:

PASS NET-01

## Configuration Drift

An inbound rule was intentionally added:

TCP/22 → 0.0.0.0/0

Baseline checker result:

FAIL NET-01

## Activity Analysis

CloudTrail recorded:

- API: AuthorizeSecurityGroupIngress
- Target: test security group
- Protocol: TCP
- Port: 22
- CIDR: 0.0.0.0/0

The configuration represented a policy violation, but no workload exposure
occurred because the test security group was not attached to a resource.

## Remediation

The insecure inbound rule was removed.

CloudTrail recorded:

RevokeSecurityGroupIngress

## Re-validation

The same baseline checker was executed again without modifying the code.

Result:

PASS NET-01

## Key Learning

Posture validation answers whether the current configuration violates the
security baseline, while CloudTrail activity analysis provides evidence of
who changed the configuration, when it changed, and which API was used.
