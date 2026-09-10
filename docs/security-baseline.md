# Security Baseline

이 문서는 개인 AWS Lab 환경에서 적용할 최소 보안 요구사항을 정의합니다.

본 Baseline은 CIS, ISO 27001 등의 공식 Compliance Standard를 구현했다고
주장하기 위한 것이 아닙니다.

프로젝트의 보안 요구사항을 먼저 정의하고,
AWS 환경에서 적용 여부를 직접 검증하기 위한 자체 Lab Baseline입니다.

## Requirements

| ID | Security Requirement | Risk | Validation |
|---|---|---|---|
| IAM-01 | Workload 및 자동화 Role에는 필요한 최소 권한만 부여한다. | 권한 오남용 및 침해 시 피해범위 확대 | IAM Policy 점검 |
| NET-01 | SSH 관리 접근은 승인된 관리자 CIDR 외의 네트워크에 노출하지 않는다. | 비인가 네트워크에서 관리 서비스에 접근할 수 있는 공격표면 확대 | Security Group 점검 |
| STO-01 | 감사로그 저장용 S3 Bucket은 Public Access를 허용하지 않는다. | 감사로그 노출 위험 | S3 Public Access 설정 점검 |
| LOG-01 | AWS Control Plane의 주요 변경을 추적할 수 있도록 CloudTrail Logging을 유지한다. | 사고 발생 시 행위 추적 곤란 | CloudTrail 상태 점검 |
| MON-01 | 주요 IAM 및 Network 설정 변경의 주체·시각·대상·변경 내용을 추적할 수 있어야 한다. | 위험한 변경행위 식별 지연 | CloudTrail Event 분석 |

## NET-01 Validation Semantics

NET-01은 SSH가 반드시 활성화되어 있어야 한다는 요구사항이 아닙니다.

SSH 접근 규칙이 존재하는 경우,
승인된 관리자 CIDR 이외의 네트워크에 SSH-capable ingress가 노출되는지를 검사합니다.

판정 결과는 `PASS`, `FAIL`, `UNKNOWN` 세 가지로 구분합니다.

### PASS

현재 검사 범위에서 승인되지 않은 SSH 노출이 확인되지 않은 상태입니다.

예:

```text
TCP/22 → <APPROVED_ADMIN_CIDR>/32
```

또는 SSH-capable ingress rule 자체가 존재하지 않는 경우입니다.

SSH 규칙이 존재하지 않아 PASS인 경우는
"SSH 접속이 가능하다"는 의미가 아니라
"승인되지 않은 SSH 노출이 확인되지 않았다"는 의미입니다.

### FAIL

명확한 Baseline 위반이 확인된 상태입니다.

예:

```text
TCP/22 → 0.0.0.0/0
TCP/0-65535 → 0.0.0.0/0
All protocols → 0.0.0.0/0
```

승인된 관리자 CIDR 이외의 IPv4 CIDR이
SSH-capable ingress rule에 사용된 경우에도 FAIL로 판정합니다.

현재 Lab Baseline은 승인된 관리자 IPv4 CIDR을 기준으로 하므로,
SSH-capable rule의 IPv6 CIDR 역시 FAIL로 판정합니다.

### UNKNOWN

현재 점검 로직만으로 안전 여부를 충분히 판단할 수 없는 상태입니다.

예:

- Security Group Reference가 SSH source로 사용된 경우
- Prefix List가 SSH source로 사용된 경우
- AWS API 호출 실패로 Security Group 상태를 조회하지 못한 경우
- 입력된 관리자 CIDR이 올바르지 않은 경우

점검에 실패하거나 현재 로직으로 평가할 수 없는 상태를
PASS로 처리하지 않습니다.

## Validation Principle

보안 상태와 변경 행위를 구분하여 확인합니다.

### Posture

현재 리소스가 Security Baseline을 준수하고 있는가?

Python/Boto3 기반 점검을 통해
현재 AWS Security Group 설정을 조회하고
`PASS`, `FAIL`, `UNKNOWN`으로 판정합니다.

### Activity

누가, 언제, 어떤 API를 통해 현재 상태를 만들었는가?

CloudTrail Event를 통해
변경 주체, 시각, 대상 리소스,
호출된 API 및 요청 내용을 확인합니다.

예를 들어 Security Group에 다음과 같은 규칙이 추가되었다면,

```text
TCP/22 → 0.0.0.0/0
```

다음 순서로 검증합니다.

1. Python/Boto3를 이용해 현재 상태가 NET-01을 위반하는지 확인합니다.
2. CloudTrail의 `AuthorizeSecurityGroupIngress` 이벤트를 통해 변경 행위를 확인합니다.
3. 변경 주체·시각·대상·프로토콜·포트·CIDR을 분석합니다.
4. 정책 위반과 실제 침해 여부를 구분하여 위험을 판단합니다.
5. 위험한 규칙을 제거합니다.
6. CloudTrail의 `RevokeSecurityGroupIngress` 이벤트로 복구 행위를 확인합니다.
7. 동일한 Baseline Checker를 다시 실행하여 정상화 여부를 검증합니다.

## Scope and Limitations

본 Baseline은 개인 AWS Lab의 보안 통제 검증을 위한 기준입니다.

현재 구현은 단일 AWS Account 및 제한된 리소스를 대상으로 하며,
CIS Benchmark, ISO 27001 또는 기업 전체의 Cloud Security Policy를
완전히 구현하거나 준수한다고 주장하지 않습니다.

현재 NET-01 점검 로직은 IPv4 CIDR,
IPv6 CIDR, Security Group Reference,
Prefix List와 같은 Security Group source 유형을 구분합니다.

다만 Security Group Reference 또는 Prefix List의
실제 유효 접근 범위까지 재귀적으로 분석하지는 않으며,
현재 로직으로 안전 여부를 판단할 수 없는 경우 `UNKNOWN`으로 처리합니다.

향후 점검 범위를 확장할 때는
Security Group Reference와 Prefix List의 유효 범위를 추가로 분석하고,
다른 보안 통제 항목도 동일한 방식으로 자동 점검할 수 있도록 확장할 수 있습니다.
