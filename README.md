# aws-secure-cloud-workload-lab

AWS 기반 Linux/Container 웹 워크로드를 직접 구축하고,
보안 Baseline을 정의하여 설정 변경과 권한 변경을 탐지·분석·개선하는 개인 프로젝트입니다.

동일한 환경에서 서비스 장애를 의도적으로 발생시킨 뒤
Network → Linux → Container → Application 계층으로 원인을 좁혀
Root Cause를 식별하고 복구하는 과정도 수행합니다.

## Objectives

이 프로젝트의 목적은 AWS 서비스를 많이 사용해보는 것이 아니라,
클라우드 환경에서 다음 과정을 직접 수행하고 이해하는 것입니다.

`Security Requirement → Implementation → Validation → Configuration Change → Detection → Analysis → Remediation → Re-validation`

운영 장애에 대해서는 다음 과정을 적용합니다.

`Symptom → Hypothesis → Evidence → Root Cause → Fix → Verification`

## Scope

- AWS EC2
- Ubuntu Linux
- Docker
- Nginx
- IAM Role / Policy
- Security Group
- CloudTrail
- EventBridge
- Python / Boto3

## Security Scenarios

### Scenario 1 - Security Group Configuration Drift

정상적인 관리 포트 접근 정책을 의도적으로 변경한 뒤,
현재 보안 상태와 CloudTrail의 변경 이벤트를 분석합니다.

### Scenario 2 - IAM Privilege Change

IAM Role의 Policy 변경 이벤트를 발생시키고,
변경 주체와 대상, 권한 및 위험성을 분석합니다.

## Troubleshooting Scenario

동작 중인 Web Service에 장애를 발생시킨 뒤,

`Client → AWS Network → Linux → Docker → Nginx`

순서로 문제 영역을 좁혀 Root Cause를 확인하고 복구합니다.

## Project Status

Design in progress
