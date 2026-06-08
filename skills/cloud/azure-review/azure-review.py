import json

def azure_review(resource):
    """
    Review Azure resources for security issues.
    """
    issues = []

    # Check for managed disk export risk
    if 'Microsoft.Compute/disks' in resource['type']:
        if 'networkAccessPolicy' not in resource or resource['networkAccessPolicy'] != 'AllowPrivate':
            issues.append({
                'id': 'AZURE-001',
                'title': 'Managed Disk Export Risk',
                'description': 'The managed disk is not configured with a private network access policy.',
                'severity': 'High'
            })

        if 'publicNetworkAccess' not in resource or resource['publicNetworkAccess'] != 'Disabled':
            issues.append({
                'id': 'AZURE-002',
                'title': 'Public Network Access Enabled',
                'description': 'The managed disk has public network access enabled.',
                'severity': 'High'
            })

        if 'diskAccessId' not in resource:
            issues.append({
                'id': 'AZURE-003',
                'title': 'Disk Access Not Configured',
                'description': 'The managed disk does not have a disk access resource configured.',
                'severity': 'Medium'
            })

    # Check for snapshot export controls
    if 'Microsoft.Compute/snapshots' in resource['type']:
        if 'networkAccessPolicy' not in resource or resource['networkAccessPolicy'] != 'AllowPrivate':
            issues.append({
                'id': 'AZURE-004',
                'title': 'Snapshot Export Risk',
                'description': 'The snapshot is not configured with a private network access policy.',
                'severity': 'High'
            })

        if 'publicNetworkAccess' not in resource or resource['publicNetworkAccess'] != 'Disabled':
            issues.append({
                'id': 'AZURE-005',
                'title': 'Public Network Access Enabled',
                'description': 'The snapshot has public network access enabled.',
                'severity': 'High'
            })

    return issues