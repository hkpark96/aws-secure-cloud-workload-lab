# AWS Secure Cloud Workload Lab

AWS 기반 Linux/Container Workload를 직접 구축하고, Security Baseline을 정의한 뒤 실제 AWS Configuration을 코드로 검증하는 개인 프로젝트입니다.

의도적인 Security Group Configuration Drift를 발생시켜 다음 과정을 직접 수행했습니다.

```text
Security Requirement
        ↓
Implementation
        ↓
Validation
        ↓
Configuration Drift
        ↓
Detection
        ↓
CloudTrail Activity Analysis
        ↓
Remediation
        ↓
Re-validation
```

단순히 AWS Service를 구성하는 것이 아니라,

**"어떤 보안 기준을 적용할 것인가 → 현재 상태가 기준을 만족하는가 → 누가 설정을 변경했는가 → 어떻게 복구하고 다시 검증할 것인가"**

를 하나의 흐름으로 구현하는 것을 목표로 했습니다.

---

## 1. Project Objectives

이 프로젝트에서는 다음 역량을 직접 구현하고 검증하는 데 집중했습니다.

- AWS Network / Compute 환경 직접 구축
- Linux / Docker 기반 Web Workload 운영
- Security Baseline 정의
- IAM Least Privilege 적용
- Python / Boto3 기반 Cloud Configuration Validation
- Security Group Configuration Drift Detection
- CloudTrail 기반 Configuration Change Activity Analysis
- Remediation 이후 동일 Logic을 이용한 Re-validation
- Unit Test를 통한 Validation Logic 검증

현재 프로젝트의 핵심 Security Scenario는 다음 흐름까지 완료했습니다.

```text
PASS
 ↓
Intentional Security Group Drift
 ↓
FAIL
 ↓
CloudTrail Activity Analysis
 ↓
Remediation
 ↓
PASS
```

---

## 2. Architecture

```text
Internet
   |
   v
Internet Gateway
   |
   v
Public Subnet
   |
   v
Security Group
   |
   v
EC2 Ubuntu
   |
   +---- Docker
   |       |
   |       v
   |     Nginx
   |
   +---- IAM Role
   |       |
   |       v
   |   ec2:DescribeSecurityGroups
   |       |
   |       v
   |   Python / Boto3
   |   Baseline Checker
   |
   v
CloudTrail
   |
   v
S3 Audit Log Bucket
```

상세 Architecture:

[`docs/architecture.md`](docs/architecture.md)

---

## 3. Implemented Components

현재 구현 및 검증이 완료된 구성입니다.

| Area | Implementation |
|---|---|
| Network | Custom VPC, Public Subnet, Internet Gateway, Route Table |
| Compute | Ubuntu EC2 |
| Workload | Docker + Nginx |
| Access Control | Security Group |
| IAM | EC2 IAM Role + Least-privilege Custom Policy |
| Audit Logging | Multi-region CloudTrail |
| Log Storage | S3 CloudTrail Audit Log Bucket |
| Storage Security | S3 Block Public Access, SSE-S3 |
| Configuration Validation | Python / Boto3 Baseline Checker |
| Validation Result | `PASS` / `FAIL` / `UNKNOWN` |
| Automated Testing | Python `unittest` — 9 Test Cases |
| Security Scenario | Security Group Configuration Drift |
| Activity Analysis | `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress` |

---

## 4. Security Baseline

프로젝트에서는 Lab 환경에 적용할 Security Baseline을 직접 정의했습니다.

현재 주요 Requirement는 다음과 같습니다.

| ID | Security Requirement |
|---|---|
| IAM-01 | Workload 및 Automation Role에는 필요한 최소 권한만 부여 |
| NET-01 | SSH 관리 접근은 승인된 관리자 CIDR 외의 네트워크에 노출하지 않음 |
| STO-01 | Audit Log S3 Bucket은 Public Access를 허용하지 않음 |
| LOG-01 | AWS Control Plane Activity를 CloudTrail로 기록 |
| MON-01 | 주요 IAM / Network 변경에 대해 Actor, Time, Target, Change를 추적할 수 있어야 함 |

이 Baseline은 개인 Lab을 위한 자체 기준이며 CIS Benchmark 또는 ISO 27001 Compliance를 구현했다고 주장하지 않습니다.

상세 Baseline:

[`docs/security-baseline.md`](docs/security-baseline.md)

---

## 5. Scenario 1 — Security Group Configuration Drift

### Baseline

Test Security Group의 SSH 접근은 승인된 Administrator CIDR만 허용하도록 구성했습니다.

```text
TCP/22 → <APPROVED_ADMIN_CIDR>
```

Baseline Checker 실행 결과:

```text
[PASS] NET-01
 - No unauthorized SSH exposure was detected.
```

### Intentional Drift

실제 Workload에 영향을 주지 않도록 EC2 또는 Network Interface에 연결되지 않은 별도의 Test Security Group을 사용했습니다.

다음 Rule을 의도적으로 추가했습니다.

```text
TCP/22 → 0.0.0.0/0
```

동일한 Checker를 다시 실행했습니다.

```text
[FAIL] NET-01
 - SSH-capable rule allows unapproved IPv4 CIDR: 0.0.0.0/0
```

Checker Logic을 수정하지 않고 실제 AWS Configuration 변화만으로 결과가 `PASS → FAIL`로 변경되는 것을 확인했습니다.

### CloudTrail Activity Analysis

CloudTrail에서 Configuration Drift를 발생시킨 Management Event를 확인했습니다.

```text
AuthorizeSecurityGroupIngress
```

주요 Request Parameter:

```text
Protocol : TCP
FromPort : 22
ToPort   : 22
CIDR     : 0.0.0.0/0
```

이를 통해 현재 Security Posture와 Configuration Change Activity를 분리하여 분석했습니다.

```text
Posture
"현재 설정이 Security Baseline을 준수하는가?"
          ↓
Python / Boto3 Baseline Checker


Activity
"누가, 언제, 어떤 API를 통해 설정을 변경했는가?"
          ↓
CloudTrail
```

Configuration Violation 자체를 침해사고로 단정하지 않고, **Policy Violation과 Confirmed Compromise를 서로 다른 판단으로 구분**했습니다.

### Remediation & Re-validation

Internet-wide SSH Rule을 제거했습니다.

CloudTrail에서 다음 Event를 확인했습니다.

```text
RevokeSecurityGroupIngress
```

그 후 동일한 Baseline Checker를 다시 실행했습니다.

```text
[PASS] NET-01
 - No unauthorized SSH exposure was detected.
```

최종적으로 다음 Security Control Cycle을 검증했습니다.

```text
Known-good Posture
      ↓
PASS
      ↓
Configuration Drift
      ↓
FAIL
      ↓
CloudTrail Activity Analysis
      ↓
Remediation
      ↓
PASS
```

상세 Scenario:

[`docs/scenarios/sg-configuration-drift.md`](docs/scenarios/sg-configuration-drift.md)

---

## 6. Baseline Checker

Python / Boto3를 이용하여 실제 AWS Security Group Configuration을 조회하고 NET-01을 검증합니다.

Implementation:

[`scripts/baseline_check.py`](scripts/baseline_check.py)

Checker의 결과는 세 가지로 구분합니다.

| Status | Meaning |
|---|---|
| `PASS` | 현재 검사 범위에서 승인되지 않은 SSH Exposure가 확인되지 않음 |
| `FAIL` | 명확한 Security Baseline 위반이 확인됨 |
| `UNKNOWN` | 현재 Checker의 범위만으로 안전 여부를 충분히 판단할 수 없음 |

예를 들어 다음 Source Type은 현재 Version에서 Effective Source를 완전히 분석하지 않으므로 `UNKNOWN`으로 처리합니다.

```text
Security Group Reference
Prefix List
```

이렇게 함으로써 **확인할 수 없는 상태를 임의로 `PASS` 처리하지 않도록 설계**했습니다.

---

## 7. Least-privilege Validation

Baseline Checker는 Static AWS Access Key를 코드에 저장하지 않습니다.

EC2 IAM Role을 통해 다음 조회 권한만 사용합니다.

```json
{
  "Effect": "Allow",
  "Action": "ec2:DescribeSecurityGroups",
  "Resource": "*"
}
```

구조는 다음과 같습니다.

```text
EC2
 ↓
IAM Role
 ↓
Read-only IAM Policy
 ↓
ec2:DescribeSecurityGroups
 ↓
Boto3 Baseline Checker
```

Checker 자체에는 Security Group Rule을 추가하거나 제거할 권한이 없습니다.

이를 통해 **Validation 기능과 Configuration Change 권한을 분리**했습니다.

---

## 8. Unit Tests

Baseline 판정 Logic은 Python `unittest`를 이용하여 검증했습니다.

Test Code:

[`scripts/test_baseline_check.py`](scripts/test_baseline_check.py)

현재 총 **9개 Test Case**를 통과했습니다.

| Test Case | Expected |
|---|---|
| SSH → Approved CIDR | `PASS` |
| SSH → Approved CIDR보다 좁은 Subnet | `PASS` |
| SSH → `0.0.0.0/0` | `FAIL` |
| Wide TCP Port Range including 22 | `FAIL` |
| All Protocols → `0.0.0.0/0` | `FAIL` |
| Security Group Reference | `UNKNOWN` |
| Prefix List | `UNKNOWN` |
| SSH-capable Rule 없음 | `PASS` |
| Invalid Approved CIDR | `UNKNOWN` |

Test Result:

```text
Ran 9 tests

OK
```

---

## 9. Security Design Decisions

이 프로젝트에서는 다음 원칙을 적용했습니다.

**Static Credential을 사용하지 않습니다.**  
AWS API 조회는 EC2 IAM Role을 사용합니다.

**Validation과 Change Permission을 분리합니다.**  
Baseline Checker에는 `DescribeSecurityGroups`만 허용합니다.

**확인할 수 없는 상태를 안전하다고 가정하지 않습니다.**  
지원하지 않는 Source Type은 `UNKNOWN`으로 처리합니다.

**Configuration Risk와 실제 Workload Exposure를 분리합니다.**  
의도적인 Drift는 실제 EC2에 연결되지 않은 Test SG에서 수행했습니다.

**Posture와 Activity를 분리하여 분석합니다.**  
Boto3는 현재 상태를 확인하고 CloudTrail은 해당 상태를 만든 변경 행위를 추적합니다.

**Policy Violation을 곧바로 침해사고로 단정하지 않습니다.**  
Compromise 판단에는 추가 Evidence와 Context가 필요하다고 판단했습니다.

---

## 10. Repository Structure

```text
aws-secure-cloud-workload-lab/
├── README.md
├── .gitignore
│
├── docs/
│   ├── architecture.md
│   ├── security-baseline.md
│   └── scenarios/
│       └── sg-configuration-drift.md
│
└── scripts/
    ├── baseline_check.py
    └── test_baseline_check.py
```

Scenario Evidence 이미지는 다음 경로에 추가할 예정입니다.

```text
docs/images/sg-drift/
```

---

## 11. Planned Extensions

현재 완료된 Security Group Drift Scenario 이후 다음 기능을 확장할 예정입니다.

### Security

- EventBridge 기반 High-risk Configuration Change Detection
- IAM Privilege Change Detection
- Security Group Reference / Prefix List Effective Source Analysis
- Centralized Multi-account Logging
- AWS Config / Security Hub 기반 Posture Management
- Infrastructure as Code 기반 Policy Validation

### Infrastructure / Troubleshooting

동일한 EC2 / Docker / Nginx Workload에서 장애를 의도적으로 발생시키고 다음 과정으로 Root Cause를 분석할 예정입니다.

```text
Symptom
  ↓
Hypothesis
  ↓
Network
  ↓
Linux
  ↓
Docker
  ↓
Nginx
  ↓
Evidence
  ↓
Root Cause
  ↓
Fix
  ↓
Verification
```

---

## 12. Project Status

### Completed

```text
AWS Workload Deployment                       ✅
Security Baseline Definition                  ✅
CloudTrail → S3 Audit Logging                 ✅
Least-privilege Validation IAM Role           ✅
Python / Boto3 NET-01 Baseline Checker        ✅
PASS / FAIL / UNKNOWN Logic                   ✅
Security Group Drift Scenario                 ✅
CloudTrail Change Activity Analysis            ✅
Remediation & Re-validation                    ✅
9 Unit Tests                                   ✅
```

### Planned

```text
Evidence Image Documentation                   ⏳
EventBridge Change Detection                   ⏳
IAM Privilege Change Scenario                  ⏳
Nginx Troubleshooting / RCA Scenario           ⏳
```

---

## 13. Key Takeaway

이 프로젝트를 통해 단순히 AWS Resource를 생성하는 것에서 끝나지 않고,

```text
보안 기준 정의
→ 실제 Cloud Configuration 조회
→ 자동 판정
→ 설정 변경 발생
→ 변경 행위 추적
→ 위험성 분석
→ 복구
→ 동일 Logic으로 재검증
```

하는 과정을 직접 구현했습니다.

특히 Security Monitoring에서 사용하는 **Evidence와 Context 기반 판단 방식**을 Cloud Security Engineering 관점의 **Baseline, IAM, Logging, Validation, Remediation**으로 확장하는 데 초점을 맞췄습니다.
