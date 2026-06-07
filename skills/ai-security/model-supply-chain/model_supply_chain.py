import re
from skills import Skill

class ModelSupplyChain(Skill):
    def __init__(self):
        super().__init__()
        self.patterns = [
            # Existing patterns...
            r"from_pretrained\([^)]*,\s*revision=[\"']?(main|latest)[\"']?",
            r"trust_remote_code\s*=\s*True",
            r"snapshot_download\([^)]*,\s*revision=[\"']?[a-f0-9]{40}[\"']?",
            r"ollama pull [^ ]+:[^ ]+",
        ]

    def audit(self, code):
        issues = []
        for pattern in self.patterns:
            if re.search(pattern, code):
                issues.append({
                    "type": "Model Supply Chain",
                    "confidence": "High",
                    "description": "Potential model supply chain vulnerability",
                })
        return issues

    def fix(self, code):
        # Implement fix logic here
        # For now, just return the original code
        return code