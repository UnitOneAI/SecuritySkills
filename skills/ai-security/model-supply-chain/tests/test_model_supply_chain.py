import unittest
from skills.ai_security.model_supply_chain.model_supply_chain import ModelSupplyChain

class TestModelSupplyChain(unittest.TestCase):
    def test_audit(self):
        skill = ModelSupplyChain()
        code = """
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("research-lab/custom-architecture-llm", revision="main")
"""
        issues = skill.audit(code)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "Model Supply Chain")

    def test_fix(self):
        skill = ModelSupplyChain()
        code = """
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("research-lab/custom-architecture-llm", revision="main")
"""
        fixed_code = skill.fix(code)
        self.assertEqual(fixed_code, code)

if __name__ == "__main__":
    unittest.main()