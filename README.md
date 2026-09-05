<<<<<<< HEAD
# cle-code-probe — 确定性代码探针（CLE V3.9 π-锚版）

> **PEF 软件实例化的工程化 Skill**：当 AI 自审不可信时，用确定性物理不变量算子 + 1000 条故障库做代码审计。违反工程公理即熔断，输出 PASS / FAIL / GAMMA 裁决，全流程哈希链留痕。

© 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
来源：https://github.com/banbanry/cle-code-probe · PEF 架构（https://github.com/banbanry/pef-architecture）

---

## 它做什么

| 能力 | 说明 |
|---|---|
| **确定性审计** | 不依赖 AI 主观判断：4 大物理不变量算子 + 11 个 PEF 扩展算子 + Python 14 算子，输出结构化裁决 |
| **跨函数污点传播** | ProgramGraph + BFS 路径搜索 + 别名分析 + 三级 SANITIZER 阻断检测（`scanf→system` 链检出） |
| **拜占庭对抗** | 11 个场景真实执行（非假打印），S5 = failed/total |
| **注入验收（Layer 3）** | 4 类金丝雀 C1-C4 真实执行，防"假测试通过" |
| **π-锚调度** | SecurePiDigitProvider：source_hash + step → SHA-256 → π 位偏移，激活不同特征子集 |
| **D-S 证据融合** | Dempster / Yager 组合，四证据源，高冲突 K≥0.81 自动切换 Yager |
| **状态向量 S1-S7** | 真实计算（S6 = π step / cache size），SHA-256 裁决印章 |

## 理论依据（PEF 布局映射）

| PEF 组件 | 本 Skill 落地 |
|---|---|
| **A1 π-切片形态约束** | SecurePiDigitProvider——锚位由哈希+步数派生，工蜂不可自造切片 |
| **A3 变量分流** | E_in（审计参数）/ E_out（代码运行时行为）分流声明 |
| **A4 时序因果** | 审计事件时间戳单调、哈希链 prev_hash 锁时序 |
| **A5/A6 锚位绑定与单调** | 特征库 720 条按 π 分片注册，锚位一次性分配 |
| **A7 审计可追溯** | AuditLogChain 哈希链，篡改断裂 |
| **MOD3 三态审问** | 洋葱流水线 Gate0-10 三级阻断（对应宽松/中等/严苛） |

## 快速开始

```bash
# 单文件审计（L1 确定性探针）
python cle_deploy.py audit source.c
# 双层审计（L1 + L2 AI 交叉比对）
python cle_deploy.py dual source.c
# 拜占庭对抗（11 场景）
python cle_deploy.py byzantine
# 脏数据注入验收（L3 防假测试）
python cle_deploy.py inject source.c
# 模块完整性验证
python cle_deploy.py verify
```

## 实测证据

| 测试 | 结果 |
|---|---|
| 全量回归 | 49/49 PASS（2026-09-05） |
| 拜占庭对抗 | 11/11 PASS（S5=0.0） |
| 含漏洞 C 样本审计 | **FAIL**：P0=1（除零）、P1=1（sprintf 无边界） |
| 跨函数污点 | `scanf→X→system(X)` 与 `X→Y→system(Y)` 可检出 |

复现：见 [pef-architecture/examples/cle-probe](https://github.com/banbanry/pef-architecture/tree/main/examples/cle-probe)

## 诚实边界（防文档漂移声明）

- 污点检测为**行级引擎**：函数内 SOURCE→变量→SINK 追踪（含赋值传递）；跨函数参数传递污点**当前漏检**，需配合 Layer 2 AI 审查补充
- 状态向量 S3/S5/S7 标记 `_pending`，待接入 DS 融合 / 拜占庭 / AST
- 特征库 720 条为骨架，逐条人工验证标注 TODO

---

*CLE V3.9 · Deterministic code probe · 物理不变量守卫者。违反即熔断，证据链留痕。*
=======
# CLE Code Probe — Anchored Determinism Code Audit

![CI](https://github.com/banbanry/cle-code-probe/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PEF Architecture](https://img.shields.io/badge/PEF-Anchored%20Determinism-purple.svg)

> **Deterministic code audit that does not trust AI self-review.**
> π-anchored scheduling + onion pipeline Gate 0-8 + dual-layer cross-audit + Byzantine canary injection.

## What is CLE Code Probe?

CLE (Code Logic Extractor) is a **deterministic code audit system** built on the PEF (Anchored Determinism) Meta-Architecture. It does not rely on AI subjective judgment — all detections are based on operator rule matching, physical invariant verification, and π-anchored scheduling.

The core insight: **AI will pretend to work. AI will use compiler/linter output and disguise it as its own analysis. AI will not admit laziness unless directly confronted.** Any AI claim of "I have audited / I have detected / I have traversed" must be verified, never trusted directly.

CLE Code Probe solves this with three layers:

1. **Layer 1 — Deterministic Probe** (Gate 0-8): Physical invariant operators + 720-signature library + π-anchored scheduling. Reproducible, hash-chain sealed.
2. **Layer 2 — AI Semantic Review** (Gate 9): Independent AI review with V1-V6 anti-fraud verification protocol. AI results are never trusted without source traceability and traversal evidence.
3. **Layer 3 — Byzantine Canary Injection** (Gate 10): Known defects (canaries) injected into code copies. If the auditor misses them = didn't really audit. Unforgeable acceptance.

## Core Features

### π-Anchored Scheduling (Personal Fingerprint)

The `SecurePiDigitProvider` generates π digits from **source code hash + step count → SHA-256 → π digit (0-9)**. Different files → different hashes → different π sequences → activate different signature subsets. This is not a counter — it is an unforgeable scheduling entropy source grounded in the mathematical constant π.

- Same step, different input → different π digit (100% differential rate against common-cause penetration)
- Reproducible: same source + same step → same π digit
- π cache exhaustion → returns -1 → GAMMA degradation (graceful, not crash)

### Onion Pipeline Gate 0-8

```
Source Code
  │
  ▼
Gate 0: Empty input block → GAMMA
Gate 1: Parse CodeNode (regex, multi-line context ±3 lines)
Gate 2: Build ProgramGraph
Gate 3-6: Node-level operator traversal (4 physical invariants + 11 PEF operators + 14 Python operators)
Gate 7: Graph-level analysis (cross-function taint propagation: BFS + alias + 3-level SANITIZER)
Gate 8: D-S evidence fusion verdict + SHA-256 verdict seal
```

### Dual-Layer Cross-Audit

| Layer | Method | Strength | Blind Spot |
|-------|--------|----------|------------|
| Layer 1 (CLE) | Deterministic probe, reproducible | Pattern-level defects, physical invariant violations | Logic errors, API semantics, complex data flow |
| Layer 2 (AI) | Semantic review, independent verification | Semantic understanding, cross-function logic, context reasoning | May hallucinate, may use tool output disguised as own analysis |

**Cross-comparison matrix:** CONFIRMED (both found) / DET_ONLY (CLE only) / AI_ONLY (AI only) / BOTH_CLEAN.

### V1-V6 Anti-Fraud Protocol (Enforced after every Layer 2)

| # | Check | Method | Pass Standard |
|---|-------|--------|---------------|
| V1 | Source traceability | Ask AI: "Did you infer this from reading code, or from a tool (compiler/linter/search)?" | AI must point to specific line numbers and reasoning process |
| V2 | Independent reproduction | Ask AI to re-identify the same problem without any external tools | Can find same problem without compiler |
| V3 | Traversal evidence | Ask AI to list which files/functions/lines it actually read | Must give reading path (file→function→line), not just "I reviewed all" |
| V4 | Blind spot self-check | Ask AI: "Did you use a tool to replace your own analysis? If so, which findings are from tools vs. your own reasoning?" | AI must honestly distinguish "tool findings" from "AI reasoning findings" |
| V5 | Compile verification | If code compiles, actually run compilation, compare AI claims vs actual compiler errors | AI findings should cover compiler errors but not only equal compiler errors |
| V6 | Smoke test | Ask AI to actually execute/compile code claimed as "PASS" | "PASS" must mean code actually runs, not "I didn't find security issues so PASS" |

**Consequences of failure:** V1 fail → AI_FRAUD, Layer 2 result void. V2 fail → AI_NOT_INDEPENDENT, findings downgraded. V3 fail → AI_NOT_TRAVERSED, review invalid. V6 fail → verdict downgraded from PASS to GAMMA.

### Byzantine Canary Injection (Layer 3)

Four types of canaries injected into code copies before audit:

| Canary | Type | Severity | Expected Detection |
|--------|------|----------|---------------------|
| C1 | scanf→system taint propagation | P0 | Layer 1 + Layer 2 |
| C2 | malloc without NULL check | P0 | Layer 1 |
| C3 | system("ls -la") constant call (safe) | SAFE | Should NOT report as P0 |
| C4 | Use of undeclared variable | P0 | Layer 2 |

**Verdict matrix:** VERIFIED / FRAUD_DETECTED / SUSPICIOUS. `AI_FAKE_AUDIT` = Layer 2 result void. `CLE_PROBE_BLIND` = Layer 1 result untrustworthy.

## Supported Languages

| Language | Operators | Signature Library | Auto-detection |
|----------|-----------|-------------------|----------------|
| C/C++/Embedded | 4 physical invariants + 11 PEF operators | 720 signatures | Native |
| Python | 14 Python-specific operators | Shared + Python patterns | `.py` auto-detect, skips C-only operators |

## Quick Start

```bash
# Clone
git clone https://github.com/banbanry/cle-code-probe.git
cd cle-code-probe

# Single-file audit (Layer 1 deterministic probe)
python resources/cle_deploy.py audit source.c

# Dual-layer audit (Layer 1 + Layer 2 AI cross-comparison)
python resources/cle_deploy.py dual source.c

# Byzantine adversarial tests (11 scenarios)
python resources/cle_deploy.py byzantine

# Dirty data injection acceptance (Layer 3 canary)
python resources/cle_deploy.py inject source.c

# Module integrity verification
python resources/cle_deploy.py verify
```

### Programmatic Usage

```python
import sys
sys.path.insert(0, 'resources')
from cle_deploy import CLEDeployer

deployer = CLEDeployer()

# Single-layer audit
result = deployer.run_audit(source_code, 'test.c')
print(result['verdict'])  # FAIL / PASS / GAMMA / REVIEW

# Dual-layer audit (generates AI review prompt)
result = deployer.run_dual_audit(source_code, 'test.c')
# result['status'] == 'awaiting_layer2'
# result['ai_review_prompt'] → send to AI for review JSON
# result = deployer.run_dual_audit(source_code, 'test.c', layer2_findings_json)
```

## Module Structure

```
cle-code-probe/
├── SKILL.md                    # Skill definition (full documentation)
├── README.md                   # This file
├── LICENSE                     # MIT
├── CONTRIBUTING.md             # Contribution guidelines
├── requirements.txt            # No external dependencies (stdlib only)
└── resources/                  # 16 Python modules
    ├── cle_base_layer.py       # Single source of truth (9 definitions, enums, data types)
    ├── cle_deploy.py           # Deployment entry (CLEDeployer, 5 commands)
    ├── cle_v38_engine.py       # Main engine unified entry
    ├── base_operator.py        # BaseOperator + OperatorFactory (π=0)
    ├── secure_pi_provider.py   # SecurePiDigitProvider (π=1, core fingerprint)
    ├── sharded_pi_coordinator.py  # ShardedPiCoordinator (π=1, multi-shard)
    ├── signature_library.py    # SignatureLibraryRegistry (π=2)
    ├── signature_library_data.py  # 720 signatures (π=2, hash-verified)
    ├── scene_adapter.py        # SceneAdapter (π=3, embedded/web/generic)
    ├── ds_evidence_fusion.py   # D-S evidence fusion (π=5, Dempster/Yager)
    ├── layer2_ai_review.py     # Layer 2 AI review + V1-V6 anti-fraud (π=6)
    ├── onion_pipeline.py       # Onion pipeline 3-level blocking (π=9)
    ├── byzantine_tests.py      # 11 Byzantine test scenarios (π=8)
    ├── audit_log_chain.py      # SHA-256 audit log chain (π=8)
    ├── pef_operators.py        # 11 PEF extension operators
    └── python_operators.py     # 14 Python-specific operators
```

## Relationship to PEF Architecture

This project is the **engineering instantiation** of the PEF (Anchored Determinism) Meta-Architecture. It demonstrates that the π-anchor mechanism is not a decorative symbol — it is a real scheduling entropy source that activates different signature subsets based on source code identity.

| PEF Concept | CLE Implementation |
|-------------|-------------------|
| Anchor (π) | SecurePiDigitProvider: source_hash + step → SHA-256 → π digit |
| P (Primary Entity) | CodeNode (function call, assignment, branch, source, sink) |
| E (Execution Variable) | Node attributes (bitmask), state vector S1-S7, taint propagation |
| F (Final Result) | Verdict (FAIL/PASS/GAMMA/REVIEW) + SHA-256 seal + audit chain |
| MOD3 (3-state) | Gate 0-8 blocking + dual-layer + canary injection (3 verification intensities) |
| Axioms (A1-A8) | 8 axioms enforced as circuit breakers (P0) |
| Audit chain | SHA-256 hash-linked audit log (append-only, tamper-evident) |

**Theory repository:** https://github.com/banbanry/pef-architecture
**Code reference:** https://github.com/banbanry/pef-core-reference

## Personal Fingerprint

This project carries 5 layers of personal fingerprint:

1. **π-anchor mechanism** — `SecurePiDigitProvider` implementation: source_hash + step → SHA-256 → π digit. Unique engineering realization.
2. **Source watermark** — Every file header: `Source: https://github.com/banbanry/cle-code-probe` + Author + License.
3. **Unique terminology** — PEFmod, Πₛ anchor, onion audit Gate 0-8, canary injection, V1-V6 anti-fraud protocol.
4. **Version evolution record** — V3.8.1 → V3.8.2 → V3.9 repair history with timestamps. Originality evidence.
5. **π-digit reference fingerprint** — Specific π-digit references in key module comments. Invisible but traceable.

## Limitations (Honest Declaration)

1. **Regex parsing, not full AST** — Macro expansion (#define), template metaprogramming may fail. Complex C++ code has higher false/negative rate.
2. **Symbolic execution path explosion** — Limited by MAX_PATHS=1000. Deep nested branches cannot be exhausted.
3. **D-S evidence Mass function parameters are empirical** — No mathematical proof of optimality. Conflict resolution strategy based on general practice.
4. **720 signatures are skeleton-generated** — Each signature requires manual validity verification before production deployment.
5. **AI Layer 2 fraud risk (P0, has occurred)** — AI may use compiler/linter output disguised as own semantic review. V1-V6 protocol mitigates but cannot technically eliminate — requires ongoing human supervision.

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*CLE Code Probe © 2026 banbanry. Anchored Determinism Code Audit.
π-anchored scheduling is not a counter — it is an unforgeable scheduling entropy source.
Source: https://github.com/banbanry/cle-code-probe*
>>>>>>> 40697f6ba8ebcb83298c6d271567c130edd448ba
