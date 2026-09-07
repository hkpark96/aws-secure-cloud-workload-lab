# Architecture

## Planned Architecture

```text
                    Internet
                       │
                       ▼
                Security Group
                       │
                       ▼
                EC2 Instance
                Ubuntu Linux
                       │
                       ▼
                    Docker
                       │
                       ▼
                    Nginx


              AWS Control Plane
                       │
        ┌──────────────┼──────────────┐
        │              │              │
       IAM         CloudTrail     EventBridge


                Python / Boto3
                       │
                       ▼
              Baseline Validation
```

## Design Intent

### Workload

AWS EC2의 Ubuntu Linux 환경에 Docker 기반 Nginx Web Service를 구성합니다.

단순히 AWS 서비스를 생성하는 것이 아니라,
실제로 보호하고 점검할 대상이 존재하는 환경을 만드는 것을 목표로 합니다.

### Identity

Workload 및 자동화 구성요소에는 IAM Role을 사용하며,
업무 수행에 필요한 최소 권한만 부여하는 것을 목표로 합니다.

### Network

서비스 포트와 관리 포트를 구분합니다.

HTTP 서비스는 외부 접근을 허용하고,
SSH 등 관리 목적 포트는 허용된 관리 Source만 접근할 수 있도록 제한합니다.

### Audit

AWS Control Plane에서 발생하는 주요 설정 및 권한 변경은
CloudTrail을 통해 추적합니다.

### Validation

Python/Boto3를 이용해 사전에 정의한 Security Baseline이
실제 AWS 환경에 적용되어 있는지 점검합니다.

### Detection

IAM 및 Network 관련 주요 설정 변경을 CloudTrail Event로 확인하고,
필요한 경우 EventBridge를 이용해 탐지 흐름으로 연결합니다.
