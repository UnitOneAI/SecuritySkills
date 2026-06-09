from .firewall_review import firewall_review

def skill_main(iac_config, deployed_state):
    return firewall_review(iac_config, deployed_state)