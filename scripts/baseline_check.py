import os
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError


REGION = os.getenv("AWS_REGION", "ap-northeast-2")
TARGET_SG_ID = os.getenv("TARGET_SG_ID")
APPROVED_ADMIN_CIDR = os.getenv("APPROVED_ADMIN_CIDR")


def rule_covers_ssh(rule):
    protocol = rule.get("IpProtocol")

    if protocol == "-1":
        return True

    if protocol != "tcp":
        return False

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port is None or to_port is None:
        return False

    return from_port <= 22 <= to_port


def main():
    if not TARGET_SG_ID or not APPROVED_ADMIN_CIDR:
        print("[UNKNOWN] Missing TARGET_SG_ID or APPROVED_ADMIN_CIDR")
        sys.exit(2)

    try:
        ec2 = boto3.client("ec2", region_name=REGION)
        response = ec2.describe_security_groups(GroupIds=[TARGET_SG_ID])
        sg = response["SecurityGroups"][0]
    except (ClientError, BotoCoreError, IndexError, KeyError) as error:
        print(f"[UNKNOWN] Unable to inspect security group: {error}")
        sys.exit(2)

    violations = []

    for rule in sg.get("IpPermissions", []):
        if not rule_covers_ssh(rule):
            continue

        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr != APPROVED_ADMIN_CIDR:
                violations.append(
                    f"SSH-capable rule allows unapproved IPv4 CIDR: {cidr}"
                )

        for ipv6_range in rule.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6")
            violations.append(
                f"SSH-capable rule allows IPv6 CIDR: {cidr}"
            )

    print(f"Target SG : {sg['GroupName']} ({sg['GroupId']})")
    print(f"Region    : {REGION}")
    print(f"Baseline  : SSH must be restricted to {APPROVED_ADMIN_CIDR}")
    print()

    if violations:
        print("[FAIL] NET-01")
        for violation in violations:
            print(f" - {violation}")
        sys.exit(1)

    print("[PASS] NET-01")
    print("SSH administrative access is restricted to the approved CIDR.")
    sys.exit(0)


if __name__ == "__main__":
    main()
  
