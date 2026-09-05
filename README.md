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
