import unittest

from baseline_check import evaluate_security_group


APPROVED = "real_public_ip/32"


class TestBaselineCheck(unittest.TestCase):

    def test_approved_ssh_cidr_is_pass(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": APPROVED}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "PASS")

    def test_narrower_cidr_inside_approved_range_is_pass(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": "10.10.10.25/32"}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(
            sg,
            "10.10.10.0/24"
        )

        self.assertEqual(status, "PASS")

    def test_public_ssh_is_fail(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "FAIL")

    def test_wide_port_range_including_ssh_is_fail(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 0,
                    "ToPort": 65535,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "FAIL")

    def test_all_protocols_public_is_fail(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "FAIL")

    def test_security_group_reference_is_unknown(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [
                        {"GroupId": "sg-example"}
                    ],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "UNKNOWN")

    def test_prefix_list_is_unknown(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [
                        {"PrefixListId": "pl-example"}
                    ],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "UNKNOWN")

    def test_no_ssh_rule_is_pass(self):
        sg = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "PrefixListIds": [],
                }
            ]
        }

        status, _ = evaluate_security_group(sg, APPROVED)

        self.assertEqual(status, "PASS")

    def test_invalid_approved_cidr_is_unknown(self):
        sg = {"IpPermissions": []}

        status, _ = evaluate_security_group(
            sg,
            "not-a-cidr"
        )

        self.assertEqual(status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
