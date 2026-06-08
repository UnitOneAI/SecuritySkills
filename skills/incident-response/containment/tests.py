import unittest
from containment import check_containment, analyze_false_positive

class TestContainment(unittest.TestCase):
    def test_containment_failure(self):
        event = {
            'aws_autoscaling': {
                'launch_template': {
                    'ami_id': 'ami-compromised-webshell-present'
                }
            }
        }
        self.assertFalse(check_containment(event))

    def test_containment_success(self):
        event = {
            'controller': 'deployment/payments-api',
            'image': 'registry.example.com/payments-api@sha256:clean-reviewed-build'
        }
        self.assertTrue(check_containment(event))

    def test_false_positive(self):
        event = {
            'controller': 'deployment/payments-api',
            'image': 'registry.example.com/payments-api@sha256:clean-reviewed-build'
        }
        self.assertTrue(analyze_false_positive(event))

if __name__ == '__main__':
    unittest.main()