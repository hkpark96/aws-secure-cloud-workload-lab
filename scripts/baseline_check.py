import ipaddress
import os
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError


REGION = os.getenv("AWS_REGION", "ap-northeast-2")
TARGET_SG_ID = os.getenv("TARGET_SG_ID")
APPROVED_ADMIN_CIDR = os.getenv("APPROVED_ADMIN_CIDR")


def rule_covers_ssh(rule):
    """Return True if an ingress rule can include TCP/22."""
    protocol = rule.get("IpProtocol")

    # -1 means all protocols
    if protocol == "-1":
        return True

    if protocol != "tcp":
        return False

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port is None or to_port is None:
        return False

    return from_port <= 22 <= to_port


def evaluate_security_group(sg, approved_admin_cidr):
    """
    Evaluate SSH exposure.

    Result precedence:
      FAIL    : a confirmed baseline violation exists
      UNKNOWN : no confirmed violation, but at least one source cannot be evaluated
      PASS    : no unauthorized SSH exposure was detected
    """

    try:
        approved_network = ipaddress.ip_network(
            approved_admin_cidr,
            strict=False
        )
    except ValueError:
        return (
            "UNKNOWN",
            [f"Invalid APPROVED_ADMIN_CIDR: {approved_admin_cidr}"]
        )

    if approved_network.version != 4:
        return (
            "UNKNOWN",
            ["Current checker expects an approved IPv4 administrator CIDR."]
        )

    violations = []
    unknowns = []
    ssh_rule_found = False

    for rule in sg.get("IpPermissions", []):
        if not rule_covers_ssh(rule):
            continue

        ssh_rule_found = True
        recognized_source = False

        # IPv4 CIDR sources
        for ip_range in rule.get("IpRanges", []):
            recognized_source = True
            cidr = ip_range.get("CidrIp")

            if not cidr:
                unknowns.append(
                    "SSH-capable IPv4 rule contains no evaluable CIDR."
                )
                continue

            try:
                source_network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                unknowns.append(
                    f"Unable to parse IPv4 CIDR: {cidr}"
                )
                continue

            if source_network != approved_network:
                violations.append(
                    f"SSH-capable rule allows unapproved IPv4 CIDR: {cidr}"
                )

        # IPv6 CIDR sources
        for ipv6_range in rule.get("Ipv6Ranges", []):
            recognized_source = True
            cidr = ipv6_range.get("CidrIpv6", "<unknown>")

            violations.append(
                f"SSH-capable rule allows IPv6 CIDR outside "
                f"the approved IPv4 baseline: {cidr}"
            )

        # Security Group reference sources
        for group_pair in rule.get("UserIdGroupPairs", []):
            recognized_source = True
            group_id = group_pair.get("GroupId", "<unknown>")

            unknowns.append(
                f"SSH-capable rule uses Security Group reference "
                f"{group_id}; current checker does not evaluate "
                f"the referenced group's effective source."
            )

        # Prefix List sources
        for prefix in rule.get("PrefixListIds", []):
            recognized_source = True
            prefix_id = prefix.get("PrefixListId", "<unknown>")

            unknowns.append(
                f"SSH-capable rule uses Prefix List "
                f"{prefix_id}; current checker does not evaluate "
                f"Prefix List contents."
            )

        if not recognized_source:
            unknowns.append(
                "SSH-capable rule has no recognized source type."
            )

    # Confirmed violation takes precedence.
    if violations:
        return "FAIL", violations + unknowns

    # No confirmed violation, but incomplete visibility.
    if unknowns:
        return "UNKNOWN", unknowns

    # No SSH rule is also safe from an SSH-exposure perspective.
    if not ssh_rule_found:
        return (
            "PASS",
            ["No SSH-capable ingress rule is present; "
             "no unauthorized SSH exposure was detected."]
        )

    return (
        "PASS",
        ["No unauthorized SSH exposure was detected."]
    )


def main():
    if not TARGET_SG_ID or not APPROVED_ADMIN_CIDR:
        print("[UNKNOWN] Missing TARGET_SG_ID or APPROVED_ADMIN_CIDR")
        sys.exit(2)

    try:
        ec2 = boto3.client("ec2", region_name=REGION)

        response = ec2.describe_security_groups(
            GroupIds=[TARGET_SG_ID]
        )

        sg = response["SecurityGroups"][0]

    except (ClientError, BotoCoreError, IndexError, KeyError) as error:
        print(f"[UNKNOWN] Unable to inspect security group: {error}")
        sys.exit(2)

    status, findings = evaluate_security_group(
        sg,
        APPROVED_ADMIN_CIDR
    )

    print(f"Target SG : {sg['GroupName']} ({sg['GroupId']})")
    print(f"Region    : {REGION}")
    print(
        "Baseline  : SSH-capable ingress must not allow "
        "sources outside the approved administrator CIDR."
    )
    print()

    print(f"[{status}] NET-01")

    for finding in findings:
        print(f" - {finding}")

    if status == "PASS":
        sys.exit(0)

    if status == "FAIL":
        sys.exit(1)

    sys.exit(2)


if __name__ == "__main__":
    main()
