# Component-Threat Matrix Template

## STRIDE Component-Threat Heatmap

Synthesize the STRIDE-per-element analysis into a heatmap-style matrix. For each component, rate the threat level (H=High, M=Medium, L=Low, N=None) per STRIDE category based on STRIDE analysis findings, then derive an overall risk.

| Component | S | T | R | I | D | E | Overall Risk |
|-----------|---|---|---|---|---|---|-------------|
| Auth Service | H | M | M | L | L | H | Critical |
| API Gateway | H | M | L | M | H | M | High |
| Database | L | H | L | H | M | M | High |
| Object Storage | L | M | L | H | L | M | Medium |
| Message Queue | L | M | L | M | M | L | Medium |

## How to Fill In

1. For each component from the DFD, review every threat identified in the STRIDE-per-element analysis.
2. Assign H/M/L/N per STRIDE column based on the highest-severity threat in that category for that component.
3. Derive Overall Risk: Critical if any H+H combination; High if 2+ H ratings; Medium if 1 H or 2+ M; Low otherwise.
4. Use this matrix to prioritize which components need the deepest mitigation analysis.
