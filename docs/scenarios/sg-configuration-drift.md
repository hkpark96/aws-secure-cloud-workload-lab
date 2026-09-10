# Security Group Configuration Drift Detection & Remediation

## 1. Objective

이 시나리오는 AWS Security Group의 SSH 관리 접근이 Lab의 Security Baseline을 준수하는지 검증하고, 다음 Security Control Lifecycle을 실제로 확인하기 위해 수행했습니다.

**Baseline → Validation → Configuration Drift → Detection → Activity Analysis → Remediation → Re-validation**

이 실험의 목적은 침해사고를 재현하는 것이 아니라, 보안 설정이 기준에서 벗어났을 때 이를 자동으로 식별하고, 해당 상태를 만든 AWS API Activity를 추적한 뒤 설정을 복구하고 다시 검증하는 과정을 확인하는 것입니다.

---

## 2. Security Baseline

### NET-01 — Restrict administrative SSH exposure

SSH 관리 접근은 승인된 관리자 CIDR 외의 네트워크에 노출되어서는 안 됩니다.

이 기준은 SSH가 반드시 활성화되어 있어야 한다는 의미가 아닙니다.

SSH-capable ingress rule이 존재하는 경우, 해당 Rule의 Source가 승인된 관리자 CIDR 범위 안에 있는지를 검사합니다.

이 시나리오에서 사용한 정상 상태는 다음과 같습니다.

```text
TCP/22 → <APPROVED_ADMIN_CIDR>/32
```

명확한 위반 예시는 다음과 같습니다.

```text
TCP/22 → 0.0.0.0/0
TCP/0-65535 → 0.0.0.0/0
All protocols → 0.0.0.0/0
```

Baseline Checker는 결과를 `PASS`, `FAIL`, `UNKNOWN`으로 구분합니다.

```text
PASS
현재 검사 범위에서 승인되지 않은 SSH exposure가 확인되지 않음

FAIL
명확한 Security Baseline 위반이 확인됨

UNKNOWN
현재 Checker의 분석 범위만으로 안전 여부를 충분히 판단할 수 없음
```

예를 들어 Security Group Reference 또는 Prefix List가 SSH Source로 사용된 경우, 현재 Checker는 실제 Effective Source를 재귀적으로 분석하지 않기 때문에 `PASS`가 아닌 `UNKNOWN`으로 처리합니다.

SSH-capable ingress rule 자체가 존재하지 않는 경우에는 SSH exposure 관점에서 `PASS`로 처리하지만, 이는 SSH connectivity가 가능하다는 의미는 아닙니다.

---

## 3. Test Safety

이 시나리오를 위해 별도의 Security Group을 생성했습니다.

```text
secure-workload-drift-test-sg
```

이 Test Security Group은 어떤 EC2 Instance 또는 Network Interface에도 연결하지 않았습니다.

따라서 의도적으로 위험한 Rule을 생성하더라도 실제 Nginx Workload가 외부에 노출되지 않도록 실험 환경을 분리했습니다.

이를 다음과 같이 구분했습니다.

- **Configuration Risk:** Internet-wide SSH Rule이 존재함
- **Actual Workload Impact:** Test SG가 실제 Resource에 연결되지 않아 Server Exposure는 발생하지 않음

즉, 보안 기준 위반 상태는 재현하되 실제 서비스 위험은 발생시키지 않는 방식으로 실험했습니다.

---

## 4. Read-only Validation Design

Baseline Checker는 Lab EC2 Instance에서 실행되며, Static AWS Access Key를 코드에 저장하지 않습니다.

대신 EC2 IAM Role을 사용해 필요한 조회 권한만 부여했습니다.

```text
EC2
  ↓
secure-workload-sg-audit-role
  ↓
secure-workload-sg-audit-policy
  ↓
ec2:DescribeSecurityGroups
  ↓
Python / Boto3 Baseline Checker
```

Custom IAM Policy는 다음 Action만 허용합니다.

```json
{
  "Effect": "Allow",
  "Action": "ec2:DescribeSecurityGroups",
  "Resource": "*"
}
```

따라서 Checker는 Security Group 상태를 조회할 수 있지만 Rule을 추가하거나 삭제할 수 없습니다.

이 구조를 통해 상태 점검 기능과 설정 변경 권한을 분리했습니다.

Implementation:

[`../../scripts/baseline_check.py`](../../scripts/baseline_check.py)

---

## 5. Normal-State Validation

초기 Test SG의 SSH Inbound Rule은 승인된 관리자 CIDR만 허용했습니다.

```text
TCP/22 → <APPROVED_ADMIN_CIDR>/32
```

Python/Boto3 기반 Baseline Checker를 실행하여 실제 AWS Security Group 상태가 NET-01을 만족하는지 확인했습니다.

초기 실험 당시 Checker는 다음과 같이 `PASS`를 반환했습니다.

```text
[PASS] NET-01
SSH administrative access is restricted to the approved CIDR.
```

![Baseline PASS](../images/sg-drift/01-baseline-pass.png)

이 결과를 Configuration Drift 발생 전의 Known-good Posture로 사용했습니다.

> **Note:** 위 캡처는 Checker의 Validation Semantics를 개선하기 전 초기 실험 결과입니다. 이후 정상 상태를 과도하게 단정하지 않도록 출력 문구와 판정 Logic을 보완했으며, 현재 Version은 `No unauthorized SSH exposure was detected.`를 출력합니다. 최종 Re-validation과 Unit Test는 개선된 Version을 기준으로 수행했습니다.

---

## 6. Configuration Drift

정상 상태를 확인한 뒤, EC2에 연결되지 않은 Test SG에 다음 Rule을 의도적으로 추가했습니다.

```text
TCP/22 → 0.0.0.0/0
```

![Intentional drift rule](../images/sg-drift/02-drift-rule-added.png)

Baseline Checker의 코드는 수정하지 않았습니다.

동일한 Checker를 다시 실행한 결과는 다음과 같습니다.

```text
[FAIL] NET-01
 - SSH-capable rule allows unapproved IPv4 CIDR: 0.0.0.0/0
```

![Baseline FAIL](../images/sg-drift/03-drift-fail.png)

AWS Resource의 실제 설정 변화만으로 Checker 결과가 `PASS`에서 `FAIL`로 변경되었습니다.

이를 통해 현재 Security Posture가 Security Baseline을 위반하는지 자동으로 판정할 수 있음을 확인했습니다.

---

## 7. CloudTrail Activity Analysis

Baseline Checker와 CloudTrail은 서로 다른 질문에 답합니다.

### Posture

> 현재 Security Group 설정이 Security Baseline을 준수하는가?

Python/Boto3 Checker가 이 질문에 답합니다.

### Activity

> 누가, 언제, 어떤 API를 사용해 현재 상태를 만들었는가?

CloudTrail이 이 질문에 답합니다.

Configuration Drift 발생 후 CloudTrail에서 다음 Management Event를 확인했습니다.

```text
AuthorizeSecurityGroupIngress
```

해당 Event의 `requestParameters`에는 다음 변경 내용이 기록되어 있었습니다.

```text
Protocol : TCP
FromPort : 22
ToPort   : 22
CIDR     : 0.0.0.0/0
```

![CloudTrail AuthorizeSecurityGroupIngress](../images/sg-drift/04-cloudtrail-authorize.png)

### Activity Interpretation

| Field | 확인 내용 |
|---|---|
| `eventSource` | `ec2.amazonaws.com` |
| `eventName` | `AuthorizeSecurityGroupIngress` |
| `awsRegion` | `ap-northeast-2` |
| `readOnly` | `false` |
| `requestParameters` | TCP/22 및 `0.0.0.0/0` 추가 요청 |
| `eventCategory` | Management Event |

이 Event를 통해 Baseline Checker에서 확인된 `FAIL` 상태가 실제 Security Group Ingress 변경 API에 의해 발생했음을 확인했습니다.

다만 이 Configuration Change 자체를 침해사고로 판단하지는 않았습니다.

**Security Policy Violation과 Confirmed Compromise는 서로 다른 판단이며, 침해 여부를 판단하려면 추가적인 Context와 Evidence가 필요합니다.**

---

## 8. Remediation

Internet-wide SSH Rule을 제거하고 승인된 관리자 CIDR Rule은 유지했습니다.

제거 대상은 다음과 같습니다.

```text
TCP/22 → 0.0.0.0/0
```

CloudTrail에서는 해당 복구 작업에 대해 다음 API Event가 기록되었습니다.

```text
RevokeSecurityGroupIngress
```

![CloudTrail RevokeSecurityGroupIngress](../images/sg-drift/05-cloudtrail-revoke.png)

CloudTrail Event에서 제거 대상 Protocol, Port, CIDR이 실제로 기록된 것을 확인했습니다.

---

## 9. Re-validation

Remediation 이후 Baseline Checker의 Validation Logic을 수정하지 않고 동일한 코드를 다시 실행했습니다.

결과는 다음과 같습니다.

```text
[PASS] NET-01
 - No unauthorized SSH exposure was detected.
```

![Remediation PASS](../images/sg-drift/06-remediation-pass.png)

이를 통해 위험한 Rule 제거 후 Security Group이 다시 정의된 Security Baseline 상태로 돌아왔음을 확인했습니다.

---

## 10. Baseline Checker Validation

실제 AWS 환경에서의 검증 외에도 `evaluate_security_group()`의 판정 Logic을 Unit Test로 검증했습니다.

Test Code:

[`../../scripts/test_baseline_check.py`](../../scripts/test_baseline_check.py)

다음 Edge Case를 포함해 총 9개 Test Case를 검증했습니다.

| Test Case | Expected Result |
|---|---|
| SSH → Approved CIDR | `PASS` |
| SSH → Approved CIDR보다 더 좁은 Subnet | `PASS` |
| SSH → `0.0.0.0/0` | `FAIL` |
| TCP 0-65535 → `0.0.0.0/0` | `FAIL` |
| All Protocols → `0.0.0.0/0` | `FAIL` |
| SSH → Security Group Reference | `UNKNOWN` |
| SSH → Prefix List | `UNKNOWN` |
| SSH-capable Rule 없음 | `PASS` |
| 잘못된 Approved CIDR 입력 | `UNKNOWN` |

실행 결과:

```text
Ran 9 tests

OK
```

이를 통해 단순히 TCP/22 단일 Rule만 검사하는 것이 아니라, SSH를 포함하는 Port Range와 All Protocol Rule, 그리고 현재 Checker가 완전히 해석할 수 없는 Source Type에 대한 처리까지 검증했습니다.

---

## 11. Result

이번 시나리오에서 다음 Security Control Cycle을 실제로 수행했습니다.

```text
Known-good Posture
      ↓
PASS
      ↓
Intentional Configuration Drift
      ↓
FAIL
      ↓
CloudTrail Activity Analysis
      ↓
AuthorizeSecurityGroupIngress
      ↓
Risk Assessment
      ↓
Remediation
      ↓
RevokeSecurityGroupIngress
      ↓
Re-validation
      ↓
PASS
```

### What Was Validated

- Security Requirement를 Machine-checkable Rule로 변환했습니다.
- Python/Boto3를 이용해 실제 AWS Security Group 설정을 조회했습니다.
- Static Access Key 대신 Least-privilege EC2 IAM Role을 사용했습니다.
- Checker가 `PASS`, `FAIL`, `UNKNOWN`을 구분하도록 설계했습니다.
- `0.0.0.0/0`, Wide Port Range, All Protocol Rule 등을 판정할 수 있도록 확장했습니다.
- Security Group Reference와 Prefix List처럼 현재 분석 범위를 벗어난 Source는 `UNKNOWN`으로 처리했습니다.
- CloudTrail을 이용해 Configuration Change를 발생시킨 AWS API Activity를 추적했습니다.
- `AuthorizeSecurityGroupIngress`와 `RevokeSecurityGroupIngress`를 통해 변경과 복구 행위를 확인했습니다.
- 동일한 Checker를 사용해 `PASS → FAIL → PASS` 변화를 검증했습니다.
- 실제 Workload를 노출하지 않고 Test SG에서 Configuration Risk를 재현했습니다.
- 9개의 Unit Test를 통해 주요 Edge Case 판정 Logic을 검증했습니다.

---

## 12. Limitations and Future Improvements

이 프로젝트는 개인 AWS Lab을 대상으로 하며 Production 수준의 Multi-account 또는 Hybrid Cloud 환경을 재현하지 않습니다.

현재 한계는 다음과 같습니다.

- 본 시나리오는 자체 정의한 Lab Security Baseline을 검증하며 CIS Benchmark 또는 ISO 27001 Compliance를 구현했다고 주장하지 않습니다.
- Configuration Drift 발생과 Remediation은 AWS Console에서 수동으로 수행했습니다.
- 현재 Checker는 Security Group의 SSH Exposure에 집중합니다.
- Security Group Reference 및 Prefix List의 실제 Effective Source를 재귀적으로 분석하지 않습니다.
- 단일 AWS Account 환경을 대상으로 합니다.
- 실험 과정의 일부 관리 작업은 AWS Account Root Console Session에서 수행했으며, Production 환경에서는 필요한 권한만 부여된 IAM Identity를 사용하는 것이 적절합니다.
- 현재는 지속적인 Enterprise-wide Posture Management 또는 Automatic Remediation을 구현하지 않았습니다.

향후 다음과 같은 방향으로 확장할 수 있습니다.

- EventBridge 기반 주요 Configuration Change Detection
- IAM Privilege Change Detection
- Security Group Reference 및 Prefix List의 Effective Source Analysis
- Centralized Multi-account Logging
- AWS Config / Security Hub / CNAPP 기반 Posture Management
- Infrastructure as Code 기반 사전 Policy Validation
- 승인된 Change와 비정상 Change를 구분하기 위한 Context Enrichment
