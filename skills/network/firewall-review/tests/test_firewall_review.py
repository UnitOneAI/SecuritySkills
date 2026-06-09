import unittest
from skills.network.firewall_review import firewall_review

class TestFirewallReview(unittest.TestCase):
    def test_hygiene_issue(self):
        iac_config = {
            'rules': [
                {'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'},
            ],
        }

        deployed_state = {
            'rules': [],
        }

        issues = firewall_review(iac_config, deployed_state)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'hygiene issue')

    def test_live_exposure(self):
        iac_config = {
            'rules': [],
        }

        deployed_state = {
            'rules': [
                {'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'},
            ],
        }

        issues = firewall_review(iac_config, deployed_state)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'live exposure')

    def test_exposure_window(self):
        iac_config = {
            'rules': [],
        }

        deployed_state = {
            'enis': [
                {'id': 'eni-ephemeral-build-runner', 'security_groups': ['sg-default-egress-all', 'sg-admin-ingress']},
            ],
        }

        issues = firewall_review(iac_config, deployed_state)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'exposure window')

if __name__ == '__main__':
    unittest.main()