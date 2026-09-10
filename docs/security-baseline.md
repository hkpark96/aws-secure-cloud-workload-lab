# Security Baseline

이 문서는 개인 AWS Lab 환경에서 적용할 최소 보안 요구 사항을 정의합니다.

본 Baseline은 CIS, ISO 27001 등의 공식 Compliance Standard를 구현했다고
주장하기 위한 것이 아닙니다.

프로젝트의 보안 요구 사항을 먼저 정의하고,
AWS 환경에서 적용 여부를 직접 검증하기 위한 자체 Lab Baseline입니다.

## Requirements

| ID | Security Requirement | Risk | Validation |
|---|---|---|---|
| IAM-01 | Workload 및 자동화 Role에는 필요한 최소 권한만 부여한다. | 권한 오남용 및 침해 시 피해 범위 확대 | IAM Policy 점검 |
| NET-01 | SSH 관리 접근은 승인된 관리자 CIDR 외의 네트워크에 노출하지 않는다. | 비인가 네트워크에서 관리 서비스에 접근할 수 있는 공격 표면 확대 | Security Group 점검 |
| STO-01 | 감사 로그 저장용 S3 Bucket은 Public Access를 허용하지 않는다. | 감사 로그 노출 위험 | S3 Public Access 설정 점검 |
| LOG-01 | AWS Control Plane의 주요 변경을 추적할 수 있도록 CloudTrail Logging을 유지한다. | 사고 발생 시 행위 추적 곤란 | CloudTrail 상태 점검 |
| MON-01 | 주요 IAM 및 Network 설정 변경의 주체·시각·대상·변경 내용을 추적할 수 있어야 한다. | 위험한 변경행위 식별 지연 | CloudTrail Event 분석 |

## NET-01 Validation Semantics

NET-01은 SSH가 반드시 활성화되어 있어야 한다는 요구 사항이 아닙니다.

SSH 접근 규칙이 존재하는 경우,
승인된 관리자 CIDR 이외의 네트워크에 SSH-capable ingress가 노출되는지에 대해 검사합니다.

판정 결과는 다음 세 가지로 구분합니다.

### PASS

현재 검사 범위에서 승인되지 않은 SSH 노출이 확인되지 않은 상태입니다.

예:

```text
TCP/22 → <APPROVED_ADMIN_CIDR>/32
