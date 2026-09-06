# CLE Code Probe — 确定性代码探针（PEF0001）

![CI](https://github.com/banbanry/cle-code-probe/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PEF Architecture](https://img.shields.io/badge/PEF-Anchored%20Determinism-purple.svg)
![PEF ID](https://img.shields.io/badge/PEF0001-Code%20Probe-green.svg)

> **当 AI 自审不可信时，用确定性物理不变量算子 + 720 条故障库做代码审计。违反工程公理即熔断，输出 PASS / FAIL / GAMMA 裁决，全流程哈希链留痕。**
>
> *Deterministic code audit that does not trust AI self-review. π-anchored scheduling + onion pipeline Gate 0-8 + dual-layer cross-audit + Byzantine canary injection.*

© 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
来源：https://github.com/banbanry/cle-code-probe · PEF 架构：https://github.com/banbanry/pef-architecture

---

## ⚡ 30 秒上手

**一句话**：AI 说"我审过了"不可信——用确定性探针 + 拜占庭金丝雀注入验证审计器本身，防"假测试通过"。

**一条命令运行**：

```bash
# 克隆并运行拜占庭对抗测试（11场景，验证探针本身）
git clone https://github.com/banbanry/cle-code-probe.git
cd cle-code-probe
python resources/cle_deploy.py byzantine
```

**预期输出**：`11/11 PASS, S5=0.0`（11个拜占庭场景全部通过，探针本身无盲区）

**审计你的代码**：

```bash
# 单文件审计（L1 确定性探针）
python resources/cle_deploy.py audit your_code.c

# 双层审计（L1 确定性 + L2 AI 交叉比对）
python resources/cle_deploy.py dual your_code.c

# 脏数据注入验收（L3 防假测试——验证审计器有没有真的审）
python resources/cle_deploy.py inject your_code.c
```

**效果图**（典型审计输出）：

```
[CLE V3.9] Deterministic Code Probe
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File: vuln_sample.c
π-anchor: π[7]=6|E|source_hash=a1b2c3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[P0] Division by zero (line 15)
     Operator: E012_DIV_BY_ZERO
     Evidence: result = numerator / denominator;
[P1] sprintf without boundary (line 23)
     Operator: E015_BUFFER_OVERFLOW
     Evidence: sprintf(buf, user_input);
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verdict: FAIL (P0=1, P1=1)
SHA-256 seal: a1b2c3d4e5f6...
Audit chain: 3 entries, tamper-evident
```

---

## 🎯 它做什么

| 能力 | 说明 |
|------|------|
| **确定性审计** | 不依赖 AI 主观判断：4 大物理不变量算子 + 11 个 PEF 扩展算子 + Python 14 算子，输出结构化裁决 |
| **跨函数污点传播** | ProgramGraph + BFS 路径搜索 + 别名分析 + 三级 SANITIZER 阻断检测（`scanf→system` 链检出） |
| **拜占庭对抗** | 11 个场景真实执行（非假打印），S5 = failed/total |
| **注入验收（Layer 3）** | 4 类金丝雀 C1-C4 真实执行，防"假测试通过" |
| **π-锚调度** | SecurePiDigitProvider：source_hash + step → SHA-256 → π 位偏移，激活不同特征子集 |
| **D-S 证据融合** | Dempster / Yager 组合，四证据源，高冲突 K≥0.81 自动切换 Yager |
| **状态向量 S1-S7** | 真实计算（S6 = π step / cache size），SHA-256 裁决印章 |

---

## 🏗️ 三层审计架构

```
Source Code
  │
  ▼
┌─────────────────────────────────────────┐
│ Layer 1 — Deterministic Probe (Gate 0-8)│
│ 物理不变量算子 + 720特征库 + π-锚调度    │
│ 可复现，哈希链密封                         │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Layer 2 — AI Semantic Review (Gate 9)   │
│ 独立 AI 审查 + V1-V6 反欺诈协议           │
│ AI 结果必须有源追溯和遍历证据才可信        │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│ Layer 3 — Byzantine Canary (Gate 10)    │
│ 已知缺陷（金丝雀）注入代码副本             │
│ 审计器漏检 = 没真审 = 不可伪造的验收      │
└─────────────────────────────────────────┘
```

### V1-V6 反欺诈协议（Layer 2 强制执行）

| # | 检查 | 方法 | 通过标准 |
|---|------|------|----------|
| V1 | 源追溯 | 问 AI："这是你从代码推断的，还是从工具（编译器/linter/搜索）得到的？" | AI 必须指向具体行号和推理过程 |
| V2 | 独立复现 | 让 AI 不用任何外部工具重新识别同一问题 | 能不用编译器找到同一问题 |
| V3 | 遍历证据 | 让 AI 列出实际读了哪些文件/函数/行 | 必须给出阅读路径（文件→函数→行），不是"我全审了" |
| V4 | 盲区自检 | 问 AI："你用工具代替自己分析了吗？哪些发现来自工具，哪些来自你自己的推理？" | AI 必须诚实区分"工具发现"和"AI推理发现" |
| V5 | 编译验证 | 如果代码能编译，实际运行编译，对比 AI 声称 vs 实际编译器错误 | AI 发现应覆盖编译器错误但不只等于编译器错误 |
| V6 | 冒烟测试 | 让 AI 实际执行/编译声称"PASS"的代码 | "PASS"必须意味着代码真的能跑，不是"我没发现安全问题所以PASS" |

**失败后果**：V1 失败 → AI_FRAUD，Layer 2 结果无效。V2 失败 → AI_NOT_INDEPENDENT，发现降级。V3 失败 → AI_NOT_TRAVERSED，审查无效。V6 失败 → 裁决从 PASS 降级为 GAMMA。

---

## 🔑 π-锚调度（个人指纹）

`SecurePiDigitProvider` 从 **源代码哈希 + 步数 → SHA-256 → π 位数字（0-9）** 生成 π 位。不同文件 → 不同哈希 → 不同 π 序列 → 激活不同特征子集。这不是计数器——这是根植于数学常数 π 的不可伪造调度熵源。

- 同一步数，不同输入 → 不同 π 位（对抗共因穿透的 100% 差异率）
- 可复现：同一源码 + 同一步数 → 同一 π 位
- π 缓存耗尽 → 返回 -1 → GAMMA 降级（优雅降级，不崩溃）

---

## 📊 实测证据

| 测试 | 结果 |
|------|------|
| 全量回归 | 49/49 PASS（2026-09-05） |
| 拜占庭对抗 | 11/11 PASS（S5=0.0） |
| 含漏洞 C 样本审计 | **FAIL**：P0=1（除零）、P1=1（sprintf 无边界） |
| 跨函数污点 | `scanf→X→system(X)` 与 `X→Y→system(Y)` 可检出 |
| 注入验收 | FRAUD_DETECTED（Layer 3 发现 Layer 1 漏检注入缺陷） |

复现：见 [pef-architecture/examples/cle-probe](https://github.com/banbanry/pef-architecture/tree/main/examples/cle-probe)

---

## 📁 模块结构

```
cle-code-probe/
├── SKILL.md                    # Skill 定义（完整文档）
├── README.md                   # 本文件
├── LICENSE                     # MIT
├── requirements.txt            # 无外部依赖（仅标准库）
└── resources/                  # 16 个 Python 模块
    ├── cle_base_layer.py       # 单一事实来源（9个定义、枚举、数据类型）
    ├── cle_deploy.py           # 部署入口（CLEDeployer，5个命令）
    ├── cle_v38_engine.py       # 主引擎统一入口
    ├── base_operator.py        # BaseOperator + OperatorFactory（π=0）
    ├── secure_pi_provider.py   # SecurePiDigitProvider（π=1，核心指纹）
    ├── sharded_pi_coordinator.py  # ShardedPiCoordinator（π=1，多分片）
    ├── signature_library.py    # SignatureLibraryRegistry（π=2）
    ├── signature_library_data.py  # 720条特征（π=2，哈希验证）
    ├── scene_adapter.py        # SceneAdapter（π=3，嵌入式/Web/通用）
    ├── ds_evidence_fusion.py   # D-S 证据融合（π=5，Dempster/Yager）
    ├── layer2_ai_review.py     # Layer 2 AI 审查 + V1-V6 反欺诈（π=6）
    ├── onion_pipeline.py       # 洋葱流水线三级阻断（π=9）
    ├── byzantine_tests.py      # 11个拜占庭测试场景（π=8）
    ├── audit_log_chain.py      # SHA-256 审计日志链（π=8）
    ├── pef_operators.py        # 11个 PEF 扩展算子
    └── python_operators.py     # 14个 Python 专用算子
```

---

## 🔗 与 PEF 架构的关系

本项目是 PEF（锚定确定性）元架构的**工程实例化**。它证明了 π-锚机制不是装饰符号——而是一个真实的调度熵源，根据源代码身份激活不同特征子集。

| PEF 概念 | CLE 实现 |
|----------|----------|
| 锚（π） | SecurePiDigitProvider：source_hash + step → SHA-256 → π 位 |
| P（主体） | CodeNode（函数调用、赋值、分支、源、汇） |
| E（执行变量） | 节点属性（位掩码）、状态向量 S1-S7、污点传播 |
| F（结果） | 裁决（FAIL/PASS/GAMMA/REVIEW）+ SHA-256 印章 + 审计链 |
| MOD3（三态） | Gate 0-8 阻断 + 双层 + 金丝雀注入（三种验证强度） |
| 公理（A1-A8） | 8条公理作为熔断器强制执行（P0） |
| 审计链 | SHA-256 哈希链接审计日志（只追加，篡改可检测） |

**理论仓库**：https://github.com/banbanry/pef-architecture
**代码参考**：https://github.com/banbanry/pef-core-reference

---

## 👤 个人指纹

本项目携带 5 层个人指纹：

1. **π-锚机制** — `SecurePiDigitProvider` 实现：source_hash + step → SHA-256 → π 位。独特工程实现。
2. **来源水印** — 每个文件头：`Source: https://github.com/banbanry/cle-code-probe` + 作者 + 许可证。
3. **独特术语** — PEFmod、Πₛ 锚、洋葱审计 Gate 0-8、金丝雀注入、V1-V6 反欺诈协议。
4. **版本演化记录** — V3.8.1 → V3.8.2 → V3.9 修复历史带时间戳。原创性证据。
5. **π 位参考指纹** — 关键模块注释中的特定 π 位引用。隐形但可追溯。

---

## ⚠️ 诚实边界（防文档漂移声明）

1. **正则解析，非完整 AST** — 宏展开（#define）、模板元编程可能失败。复杂 C++ 代码误报/漏报率更高。
2. **符号执行路径爆炸** — 受 MAX_PATHS=1000 限制。深层嵌套分支无法穷尽。
3. **D-S 证据 Mass 函数参数是经验值** — 无最优性数学证明。冲突解决策略基于通用实践。
4. **720 条特征是骨架生成** — 每条特征在生产部署前需要人工有效性验证。
5. **AI Layer 2 欺诈风险（P0，已发生过）** — AI 可能用编译器/linter 输出伪装成自己的语义审查。V1-V6 协议缓解但无法技术消除——需要持续人工监督。
6. **污点检测为行级引擎** — 函数内 SOURCE→变量→SINK 追踪（含赋值传递）；跨函数参数传递污点当前漏检，需配合 Layer 2 AI 审查补充。

---

## 📜 许可证

MIT License — 详见 [LICENSE](LICENSE)。

---

*CLE Code Probe © 2026 banbanry. 锚定确定性代码审计。*
*π-锚调度不是计数器——它是不可伪造的调度熵源。*
*来源：https://github.com/banbanry/cle-code-probe*
