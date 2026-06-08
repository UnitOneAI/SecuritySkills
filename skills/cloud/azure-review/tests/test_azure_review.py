import unittest
from azure_review import azure_review

class TestAzureReview(unittest.TestCase):
    def test_managed_disk_export_risk(self):
        resource = {
            'type': 'Microsoft.Compute/disks',
            'networkAccessPolicy': 'AllowPrivate',
            'publicNetworkAccess': 'Disabled',
            'diskAccessId': 'example-disk-access-id'
        }
        issues = azure_review(resource)
        self.assertEqual(len(issues), 0)

    def test_managed_disk_public_export_path_allowed(self):
        resource = {
            'type': 'Microsoft.Compute/disks',
            'networkAccessPolicy': 'AllowAll',
            'publicNetworkAccess': 'Enabled'
        }
        issues = azure_review(resource)
        self.assertEqual(len(issues), 2)

    def test_snapshot_export_controls(self):
        resource = {
            'type': 'Microsoft.Compute/snapshots',
            'networkAccessPolicy': 'AllowPrivate',
            'publicNetworkAccess': 'Disabled'
        }
        issues = azure_review(resource)
        self.assertEqual(len(issues), 0)

    def test_snapshot_export_risk(self):
        resource = {
            'type': 'Microsoft.Compute/snapshots',
            'networkAccessPolicy': 'AllowAll',
            'publicNetworkAccess': 'Enabled'
        }
        issues = azure_review(resource)
        self.assertEqual(len(issues), 2)

if __name__ == '__main__':
    unittest.main()