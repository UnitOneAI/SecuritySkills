import unittest
from skills.ai_security.model_supply_chain.model_supply_chain import ModelSupplyChain

class TestModelSupplyChain(unittest.TestCase):
    def test_audit(self):
        code = """
        from transformers import AutoModelForCausalLM
        model = AutoModelForCausalLM.from_pretrained(
            "research-lab/custom-architecture-llm",
            revision="main",
            trust_remote_code=True,
        )
        """
        skill = ModelSupplyChain()
        issues = skill.audit(code)
        self.assertIn("Model loaded with trust_remote_code=True", issues)

    def test_get_provenance_gates(self):
        skill = ModelSupplyChain()
        gates = skill.get_provenance_gates()
        self.assertIn("trust_remote_code", gates)
        self.assertIn("final_artifact_provenance", gates)
        self.assertIn("signed_slsa_attestation", gates)