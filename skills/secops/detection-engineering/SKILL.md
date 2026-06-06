# Detection Engineering

## Overview
Detection Engineering is the practice of designing, implementing, and maintaining security detection rules (e.g., Sigma, YARA, Splunk SPL) to identify malicious activity within an environment. This skill focuses on creating high-fidelity alerts that minimize false positives while maximizing coverage.

## Evidence Gates
To demonstrate proficiency in this skill, the following evidence gates must be satisfied:

### 1. Negative Control
A detection rule must be validated against known benign behavior to ensure it does not trigger on standard operational activities.
- **Requirement:** Provide a test case or log sample representing a benign event that matches the rule's logic but should **not** trigger an alert.
- **Validation:** The rule must return a negative result for this input.
- **Example:** A PowerShell rule detecting encoded commands must not trigger on standard administrative scripts that use base64 for legitimate configuration loading.

### 2. Telemetry Sufficiency
The detection rule must rely on telemetry that is consistently available and of sufficient quality in the target environment.
- **Requirement:** Identify the specific log source and fields required. Verify that the environment generates these logs with the necessary granularity.
- **Validation:** Demonstrate that the required fields (e.g., `CommandLine`, `ParentImage`, `User`) are present in the live log stream and not truncated or masked.
- **Example:** A rule requiring `ParentImage` to detect process injection must be rejected if the endpoint agent is configured to only log `Image` and `CommandLine`.

### 3. Backend Conversion
The detection logic must be successfully converted to the specific query language of the target SIEM or detection backend.
- **Requirement:** Provide the converted rule (e.g., Splunk SPL, Elastic Query, Azure KQL) alongside the source rule (e.g., Sigma).
- **Validation:** The converted rule must execute without syntax errors and return the expected results against the test dataset.
- **Example:** A Sigma rule targeting Windows Process Creation must be converted to a valid Splunk SPL query that correctly filters `EventCode=4688` and parses the `CommandLine` field.

## Example Rule Structure
Below is an example of a detection rule that adheres to these gates.