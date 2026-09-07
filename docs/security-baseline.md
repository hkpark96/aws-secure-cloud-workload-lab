# Security Baseline

이 문서는 개인 AWS Lab 환경에서 적용할 최소 보안 요구사항을 정의합니다.

본 Baseline은 CIS, ISO 27001 등의 공식 Compliance Standard를 구현했다고 주장하기 위한 것이 아닙니다.

프로젝트의 보안 요구사항을 먼저 정의하고,
AWS 환경에서 적용 여부를 직접 검증하기 위한 자체 Lab Baseline입니다.

## Requirements

| ID | Security Requirement | Risk | Validation |
|---|---|---|---|
| IAM-01 | Workload 및 자동화 Role에는 필요한 최소 권한만 부여한다. | 권한 오남용 및 침해 시 피해범위 확대 | IAM Policy 점검 |
| NET-01 | SSH 등 관리 포트를 0.0.0.0/0에 공개하지 않는다. | 인터넷에서 관리 서비스에 직접 접근 가능 | Security Group 점검 |
| STO-01 | 감사로그 저장용 S3 Bucket은 Public Access를 허용하지 않는다. | 감사로그 노출 위험 | S3 Public Access 설정 점검 |
| LOG-01 | AWS Control Plane의 주요 변경을 추적할 수 있도록 CloudTrail Logging을 유지한다. | 사고 발생 시 행위 추적 곤란 | CloudTrail 상태 점검 |
| MON-01 | 주요 IAM 및 Network 설정 변경의 주체·시각·대상·변경 내용을 추적할 수 있어야 한다. | 위험한 변경행위 식별 지연 | CloudTrail Event 분석 |

## Validation Principle

보안 상태와 변경 행위를 구분하여 확인합니다.

### Posture
현재 리소스가 Security Baseline을 준수하고 있는가?

### Activity
누가, 언제, 어떤 API를 통해 현재 상태를 만들었는가?

예를 들어 Security Group의 SSH 포트가 0.0.0.0/0에 공개되어 있다면,

1. Python/Boto3를 이용해 현재 상태가 NET-01을 위반하는지 확인합니다.
2. CloudTrail을 이용해 해당 설정을 누가 언제 변경했는지 확인합니다.
3. 변경 목적과 위험도를 분석합니다.
4. 설정을 복구합니다.
5. 다시 Baseline을 검사하여 정상화 여부를 확인합니다.
