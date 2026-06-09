import json

def firewall_review(iac_config, deployed_state):
    """
    Review firewall configuration for potential security issues.

    Args:
    iac_config (dict): Infrastructure as Code configuration.
    deployed_state (dict): Deployed state of the firewall.

    Returns:
    list: List of potential security issues.
    """
    issues = []

    # Check for rules present in IaC but not applied
    for rule in iac_config.get('rules', []):
        if rule not in deployed_state.get('rules', []):
            issues.append({
                'type': 'hygiene issue',
                'description': f"Rule {rule} is present in IaC but not applied",
            })

    # Check for rules present in deployed state but not in IaC
    for rule in deployed_state.get('rules', []):
        if rule not in iac_config.get('rules', []):
            issues.append({
                'type': 'live exposure',
                'description': f"Rule {rule} is present in deployed state but not in IaC",
            })

    # Check for ephemeral interfaces inheriting broad security groups
    for eni in deployed_state.get('enis', []):
        if eni.get('security_groups', []) == ['sg-default-egress-all', 'sg-admin-ingress']:
            issues.append({
                'type': 'exposure window',
                'description': f"ENI {eni.get('id')} is inheriting broad security groups",
            })

    return issues

def main():
    iac_config = {
        'rules': [
            {'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'},
        ],
    }

    deployed_state = {
        'rules': [
            {'protocol': 'tcp', 'port': 22, 'cidr': '0.0.0.0/0'},
            {'protocol': 'tcp', 'port': 80, 'cidr': '0.0.0.0/0'},
        ],
        'enis': [
            {'id': 'eni-ephemeral-build-runner', 'security_groups': ['sg-default-egress-all', 'sg-admin-ingress']},
        ],
    }

    issues = firewall_review(iac_config, deployed_state)

    for issue in issues:
        print(json.dumps(issue, indent=4))

if __name__ == '__main__':
    main()