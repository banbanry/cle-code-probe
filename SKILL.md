---
name: "cle-code-probe"
description: "Deterministic code audit via CLE V3.8.2 physical-invariant probes (4 operators + 1000 fault library + onion pipeline Gate0-10 + multi-line context window + string literal stripping + cross-function taint propagation with BFS/alias/sanitizer + D-S evidence fusion + SecurePiDigitProvider hash-offset π scheduling + Gate0-8 independent blocking verification + state vector S1-S7 + SHA-256 verdict seal + dual-layer cross-audit with AI semantic review). Invoke when auditing C/embedded security, when AI self-audit is untrusted, when probe-based review is requested, or when cross-validation between deterministic probes and AI review is needed."
---

# CLE V3.8.2 代码探针系统 · 物理不变量守卫者

## 支持语言

- **C/C++/嵌入式**：4大物理不变量算子 + 11个PEF扩展算子（原生支持）
- **Python**：14个Python特有的审计算子（V3.8.2扩展），自动检测`.py`文件后加载，跳过C特有算子

## 核心理念

本技能执行**确定性代码审计**，不依赖AI主观判断。通过物理不变量算子 + 1000条PEF/MOD故障库匹配 + 洋葱流水线Gate0-8，输出结构化的PASS/FAIL/GAMMA裁决。V3.8.2新增跨函数污点传播(BFS+别名+SANITIZER三级阻断)、D-S证据融合集成、SecurePiDigitProvider哈希偏移π调度、Gate0-8独立阻断验证、状态向量S1-S7完整计算和SHA-256裁决印章。

## 快速开始

### 模块路径

所有Python模块位于本Skill目录下的 `resources/` 子目录，是自包含的：

```bash
SKILL_DIR="$(dirname "$(find ~/.trae-cn/skills .trae/skills -name 'SKILL.md' -path '*cle-code-probe*' 2>/dev/null | head -1)")"
export PYTHONPATH="$SKILL_DIR/resources:$PYTHONPATH"
```

### 命令行调用

```bash
# 单文件审计 (Layer 1 确定性探针 + PEF扩展)
python3 "$SKILL_DIR/resources/cle_deploy.py" audit source.c

# 双层审计 (Layer 1 + Layer 2 AI交叉比对)
python3 "$SKILL_DIR/resources/cle_deploy.py" dual source.c

# 拜占庭对抗测试 (11个场景)
python3 "$SKILL_DIR/resources/cle_deploy.py" byzantine

# 脏数据注入验收 (Layer 3 防假测试)
python3 "$SKILL_DIR/resources/cle_deploy.py" inject source.c

# 模块完整性验证
python3 "$SKILL_DIR/resources/cle_deploy.py" verify
```

### 编程式调用

```python
import sys, os
# 自动定位Skill目录
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(SKILL_DIR, 'resources'))
from cle_deploy import CLEDeployer

deployer = CLEDeployer()

# 单层审计
result = deployer.run_audit(source_code, 'test.c')
print(result['verdict'])  # FAIL / PASS / GAMMA / REVIEW

# 双层审计 (生成AI审查提示)
result = deployer.run_dual_audit(source_code, 'test.c')
# → result['status'] == 'awaiting_layer2'
# → result['ai_review_prompt'] 发给AI获取审查JSON
# → deployer.run_dual_audit(source_code, 'test.c', layer2_findings_json)
```

## 公底层定义 (防数据污染)

**模块:** `cle_base_layer.py` — 所有模块的单一事实来源(Single Source of Truth)

### 九大定义

| # | 名称 | 用途 | 防止的问题 |
|---|------|------|-----------|
| 1 | NodeAttr位掩码 | 12个节点属性枚举 | 不同模块定义不同值 |
| 2 | Severity/Verdict枚举 | P0/P1/GAMMA/INFO + FAIL/REVIEW/PASS/GAMMA | 字符串硬编码拼写错误 |
| 3 | PEF三层映射 | P/E/F/MOD→算子映射 | AI混淆检测边界 |
| 4 | 核心数据类型 | CodeNode/AuditEvent/StateVector | dict/dataclass混用 |
| 5 | 状态向量S1-S7 | 7个分量+健康阈值 | 各模块阈值不一致 |
| 6 | SystemConfig | 所有物理极限参数集中管理 | 硬编码无法统一调整 |
| 7 | ModuleRegistry | 模块元信息+依赖链追踪 | 循环依赖/缺失依赖 |
| 8 | 公共工具函数 | SHA-256/注释剥离/字符串剥离 | 不同算法导致不一致 |
| 9 | API入口 | get_version/get_module_info | 版本信息分散 |

### 导出接口

```python
from cle_base_layer import *
# 类: NodeAttr, Severity, Verdict, CodeNode, AuditEvent, StateVector, SystemConfig, ModuleRegistry
# 函数: sha256_hash, strip_c_comments, strip_string_literals, has_null_check_in_context
# 函数: get_version, get_module_info, get_dependency_chain
```

## 模块文件清单与导出

| 模块文件 | Phase | 关键导出(__all__) |
|---------|-------|-------------------|
| `cle_base_layer.py` | 0 | NodeAttr, Severity, Verdict, CodeNode, AuditEvent, StateVector, SystemConfig, ModuleRegistry |
| `cle_probe_engine.py` | 1 | AuditEvent, run_probe, gate0_empty_block, gate1_parse_nodes, gate2_build_graph, gates3_6_node_operators, gate7_graph_operators, gate8_verdict, op_time_monotonicity, op_resource_bound, op_state_boundedness |
| `fault_library_1000.json` | 1 | 1000条PEF/MOD故障 (JSON数据文件) |
| `ds_evidence_fusion.py` | 2 | MassFunction, Hypothesis, dempster_combine, yager_combine, fuse_evidence, ds_fusion_pipeline, ds_verdict, compute_s3_confidence |
| `byzantine_tests.py` | 3 | ByzantineDefense, run_all_byzantine_tests, test_01~test_11 |
| `taint_propagation.py` | 4 | TaintPropagationAnalyzer, ProgramGraph, GraphBuilder, CodeNode, taint_analysis_pipeline |
| `integrated_pipeline.py` | 4 | run_integrated_probe, enhanced_gate1_parse, parse_with_taint_module, gate7_enhanced_taint, gate8_ds_verdict |
| `secure_pi_provider.py` | 5 | SecurePiDigitProvider, StateVectorCalculator, VerdictSeal, run_phase5_pipeline |
| `layer2_cross_audit.py` | L2 | run_dual_layer_audit, finalize_cross_audit, generate_cross_report, run_layer2_deterministic_fallback |
| `layer3_injection_verifier.py` | L3 | Canary, CanarySet, inject_canaries, verify_layer1_canaries, verify_layer2_canaries, run_injection_verification |
| `pef_operators.py` | PEF扩展 | PlaceholderDetector, LogicChainVerifier, DeadCodeDetector, MathPropertyVerifier, StringLiteralValidator, UnimplementedDeclDetector, BufferOverflowDetector, UninitMemoryDetector, ResourceLeakDetector, IntegerOverflowDetector, PathCoverageAnalyzer, RaceConditionDetector, run_pef_operators |
| `cle_deploy.py` | 部署 | CLEDeployer, DeployConfig |

### 部署入口 (cle_deploy.py)

`CLEDeployer` 类是唯一的外部调用入口，内部连接所有模块：

```
CLEDeployer.run_audit(source_code)
  └── run_phase5_pipeline()          # Phase 5入口
       └── run_integrated_probe()    # Phase 4集成流水线
            ├── gate0_empty_block()  # Phase 1: Gate 0
            ├── enhanced_gate1_parse() + parse_with_taint_module()  # Phase 4: 双解析器
            ├── gate2_build_graph()  # Phase 1: Gate 2
            ├── gates3_6_node_operators()  # Phase 1: Gate 3-6
            ├── gate7_enhanced_taint()  # Phase 4: Gate 7
            └── gate8_ds_verdict()  # Phase 2+4: Gate 8
       └── SecurePiDigitProvider()   # Phase 5: π调度
       └── StateVectorCalculator()  # Phase 5: S1-S7
       └── VerdictSeal.generate_seal()  # Phase 5: 印章
  └── run_pef_operators()            # PEF扩展: 11算子扫描
       ├── PlaceholderDetector (E033)     # 空包占位符
       ├── LogicChainVerifier (E056)      # 逻辑链断裂
       ├── DeadCodeDetector (E034)        # 死代码
       ├── MathPropertyVerifier (E022)    # 数学性质
       ├── StringLiteralValidator (E040)  # 字符串有效性
       ├── UnimplementedDeclDetector (E035) # 未实现声明
       ├── BufferOverflowDetector (E039)  # 缓冲区溢出
       ├── UninitMemoryDetector (E041)   # 未初始化内存
       ├── ResourceLeakDetector (E043)    # 资源泄漏
       ├── IntegerOverflowDetector (E150) # 整数溢出
       └── PathCoverageAnalyzer (E049)    # 路径覆盖
       └── RaceConditionDetector (E042)   # 数据竞争
  → PEF发现合并到findings, P0自动升级裁决
```

`CLEDeployer.run_dual_audit(source_code)` 在 `run_audit()` 完成后：
  1. 生成L2 AI审查提示(15类全量审查清单)
  2. 执行L2确定性回退(run_layer2_deterministic_fallback) — PEF算子作为AI未返回结果时的安全网
  3. 等待外部AI填充审查JSON → finalize_cross_audit交叉比对

`DeployConfig` 继承 `SystemConfig` 全部参数，新增运行时配置：

| 配置项 | 默认值 | 来源 |
|--------|--------|------|
| MAX_PATHS | 1000 | SystemConfig |
| TIMEOUT_SECONDS | 30 | SystemConfig |
| PI_CACHE_SIZE | 100 | SystemConfig |
| MAX_LINE_LENGTH | 10000 | SystemConfig |
| NULL_CHECK_WINDOW | 3 | SystemConfig |
| BYZANTINE_TOTAL | 11 | SystemConfig |
| DS_CONFLICT_LOW | 0.5 | SystemConfig |
| DS_CONFLICT_HIGH | 0.75 | SystemConfig |

## V3.9.2 算子迭代（2026-09-05 补充检测盲区）

**背景**：第三方对照测试发现 CLE 在 gets 危险函数和 malloc NULL 检查上存在检测盲区，与基础正则 Linter 对照后确认需补充。

**新增算子（2个，PEF算子库从12个扩展到14个）**：

| 算子 | 编号 | 检测能力 | 严重级别 |
|------|------|---------|---------|
| `DangerousFunctionDetector` | E057 | gets/vsprintf/scanf(%s)/getwd/crypt 等危险函数检测 | P0-P2 |
| `MallocNullCheckDetector` | E058 | malloc/calloc/realloc 返回值 NULL 检查追踪（上下文分析，5行窗口） | P0 |

**关键设计**：
- `DangerousFunctionDetector` 不重复检测 strcpy/sprintf/strcat（已由 `BufferOverflowDetector` 覆盖），只检测真正独特的危险函数
- `MallocNullCheckDetector` 做上下文分析：malloc 后 5 行内检查是否有 `if (var == NULL)` / `if (!var)` / `if (NULL == var)` 等 NULL 检查模式，有检查则不告警（避免误报）
- 两个算子均跳过注释行，避免误报

**实测验证（5个标准测试样本）**：

| 样本 | gets检测 | malloc NULL检测 | 不误报 |
|------|---------|----------------|--------|
| 01_basic_vuln.c | — | ✅ MALLOC_NULL_7 (P0) | — |
| 03_dangerous_functions.c | ✅ DANGER_FUNC_10 (P0) | — | — |
| 04_hardcoded_leak.c | — | ✅ MALLOC_NULL_11 (P0) | — |
| 05_clean_code.c | — | — | ✅ 有NULL检查的malloc不误报 |

**回归测试**：Byzantine 11/11 PASS，S5=0.0，healthy=True；注入验收 VERIFIED；新算子未破坏现有功能。

## V3.9.1 发行状态修订（2026-09-05 真实测试后）

**发行包与文档差异声明（防文档漂移）：**

| 声称能力 | 实际状态 | 说明 |
|---|---|---|
| 跨函数污点传播（BFS+别名+SANITIZER三级） | ✅ **跨函数 BFS 已实现**（2026-09-05） | 函数调用图 + 形实参映射 + 不动点迭代；`scanf→step2→sink→system` 三级链实测检出（TAINT_CROSS_FUNCTION, P0）。**别名分析/SANITIZER 三级阻断**仍待补全 |
| Layer3 注入验收 | ✅ 可用 | 4 类金丝雀 C1-C4 真实执行；2026-09-05 修复 C1 漏检（补写污点引擎后 FRAUD_DETECTED→VERIFIED） |
| 状态向量 S3/S5/S7 | ⚠️ 部分真实 | S6 真实计算；S3/S5/S7 标记 `_pending` 待接入 DS 融合/拜占庭/AST |

**诚实边界（实测确认）：**
- 污点检测为行级：`scanf→X→system(X)` 与 `X→Y→system(Y)` 可检出；跨函数参数传递污点**当前漏检**，使用时应配合 Layer 2 AI 审查补充。
- 4 大物理算子 + PEF 11 算子 + Python 14 算子运行正常；`audit`/`byzantine`/`inject` 三命令真实可执行。

## V3.9 修复记录 (π锚时序修复 T-22)

### π锚修复总览 (2026-09-02)
基于15万字设计文档的记忆锚点向量，按π=0→9顺序执行18个修复任务，解决长文档实现偏移问题。

| π锚 | 修复内容 | 新增模块 |
|-----|---------|---------|
| π=0 | AuditContext数据类、BaseOperator+OperatorFactory、B06/B07/B08 bug修复 | base_operator.py |
| π=1 | SecurePiDigitProvider真实实现、π调度激活、ShardedPiCoordinator | secure_pi_provider.py, sharded_pi_coordinator.py |
| π=2 | SignatureLibraryRegistry、720条特征库骨架 | signature_library.py, signature_library_data.py |
| π=3 | SceneAdapter场景适配器 | scene_adapter.py |
| π=4 | 状态向量S1-S7真实计算(修复B02/B04硬编码) | - |
| π=5 | D-S证据融合(Dempster/Yager+四大证据源) | ds_evidence_fusion.py |
| π=6 | L2 AI审查接口+V1-V6反欺诈协议 | layer2_ai_review.py |
| π=7 | L3金丝雀C4未声明变量检测(修复B05) | - |
| π=8 | ByzantineTestSuite 11场景真实执行(修复B01假打印)、AuditLogChain | byzantine_tests.py, audit_log_chain.py |
| π=9 | OnionPipeline三级阻断、CLE_V38_Engine主引擎 | onion_pipeline.py, cle_v38_engine.py |

**关键修复**:
- B01(P0): byzantine命令从假print改为真实11场景执行
- B02/B04(P1): 状态向量6/7维从硬编码改为真实计算
- B03(P1): secure_pi_provider从注册无实现改为真实模块
- B05(P1): L3金丝雀C4从无检测逻辑改为未声明变量扫描
- B06/B07/B08(P2/P3): 除法检测粗糙、循环内import、__import__重复调用

**验证**: 49/49全量回归通过，11/11拜占庭测试通过，720条特征库哈希完整。

## V3.8.2 修复记录

### 第四阶段 (跨函数污点传播 + 集成流水线)
- **OP_TaintPropagation 完整重写**: 替换单函数taint_table匹配，实现ProgramGraph + BFS路径搜索 + 别名分析(含参数传递别名映射) + 三级SANITIZER阻断检测
- **SANITIZER阻断三级检测**: 1)函数内行号检查 2)BFS路径中间函数 3)SOURCE之后/SINK之前的中间调用函数
- **参数传递别名映射**: 实参↔形参双向别名(sanitize_input(buf)→input与buf互为别名)，解决跨函数变量名不匹配问题
- **集成洋葱流水线**: `integrated_pipeline.py` 统一Gate 0-8，双解析器(增强主引擎+污点传播模块)
- **增强解析器**: 为所有函数调用创建节点(原版仅创建已知模式节点)，修复printf/Hal_GetTick等函数的GAMMA误判
- **D-S融合集成Gate 8**: S3置信度使用Bel/Pl函数计算，P1发现触发REVIEW(不被DS融合覆盖为PASS)
- **算术语句节点**: 新增ARITHMETIC节点类型，检测无函数调用的除法语句
- **测试覆盖**: 15个集成测试场景全部通过

### 第五阶段 (SecurePi + Gate独立阻断 + S1-S7 + 裁决印章)
- **SecurePiDigitProvider**: 基于源码哈希+步数联合SHA-256生成π数字(0-9)，相同step不同输入→不同π(抗共因穿透100%差异率)，可复现性验证通过，π缓存耗尽返回-1→GAMMA降级
- **故障库π绑定**: 通用0-3/DOC=4/MOD=5/LLM=6/WEB=7/EVASION=8-9，π数字调度激活对应故障库
- **Gate0-8独立阻断验证**: 12个阻断场景全部通过(Gate0空输入/Gate1零节点/Gate2图无效/Gate3时间/Gate4资源/Gate5状态/Gate6属性/Gate7污点P0/P1/Gate8 DS-FAIL/GAMMA/π耗尽)
- **状态向量S1-S7完整计算**: StateVectorCalculator独立计算7个状态分量，健康阈值(S3>=0.8/S5<=0.2/S6<0.8)，不依赖base_result默认值(防篡改)
- **裁决印章(VerdictSeal)**: SHA-256三层哈希链(source_hash + hash_self + hash_chain)，篡改检测(verdict FAIL→PASS → hash_self不匹配 → 检测通过)
- **完整第五阶段流水线**: `secure_pi_provider.py` 集成π调度+Gate验证+状态向量+印章，11个测试全部通过
- **实现模块**: `secure_pi_provider.py`

### PEF算子扩展阶段 (11个E层算子接入管线)

**来源**: 从PEF算子库500+条中系统性筛选11个E层算子，适配为CLE确定性探针

**第一批5+1个算子 (覆盖空包占位符/逻辑链断裂/死代码):**

| PEF编号 | 算子来源 | CLE适配类 | 检测能力 |
|---------|---------|-----------|---------|
| E033 | Frama-C | PlaceholderDetector | 空包占位符(TODO/FIXME/暂不实现/空函数体) |
| E056 | CEGAR | LogicChainVerifier | 逻辑链断裂(load/init返回值未检查/未初始化使用/死参数) |
| E034 | Astree | DeadCodeDetector | 死代码/死参数(kd=0.0导致路径失效) |
| E022 | Z3 SMT | MathPropertyVerifier | 数学性质(static_cast窄化/取模碰撞/clamp范围) |
| E040 | UBSan | StringLiteralValidator | 字符串有效性(find("NULL_check")等无效模式) |
| E035 | CBMC | UnimplementedDeclDetector | 未实现声明(头文件声明但源文件无实现) |

**第二批6个算子 (覆盖内存安全/资源泄漏/路径覆盖):**

| PEF编号 | 算子来源 | CLE适配类 | 检测能力 |
|---------|---------|-----------|---------|
| E039 | ASan | BufferOverflowDetector | 缓冲区溢出(find()返回npos直接substr/数组无边界检查) |
| E041 | MSan | UninitMemoryDetector | 未初始化内存(声明后未赋值参与运算/new后未init) |
| E043 | Valgrind | ResourceLeakDetector | 资源泄漏(文件句柄未关闭/new后无delete/异常路径泄漏) |
| E150 | CBMC | IntegerOverflowDetector | 整数溢出(乘法无范围检查/移位丢符号位/窄化转换) |
| E049 | KLEE | PathCoverageAnalyzer | 路径覆盖(恒真恒假条件/switch缺default/return后不可达/嵌套过深) |
| E042 | TSan | RaceConditionDetector | 数据竞争(静态变量无锁/check-then-act/public成员暴露) |

**管线集成修复 (3个致命断裂修复):**
- **F1 PEF接入L1管线**: `run_audit()` 完成Phase 5后自动调用`run_pef_operators()`，95个发现合并到findings，P0自动升级裁决
- **F2 L2提示词修复**: 从10类盲区→15类全量审查清单，删除"不要重复L1模式"指令，删除50000字符截断，新增来源溯源要求
- **F3 L2确定性回退**: 新增`run_layer2_deterministic_fallback()`，当AI未返回结果时PEF算子作为安全网，明确标记来源不冒充AI

**验证结果**: 河图洛书C++代码从L1=0发现/verdict=PASS(假PASS) → L1=95发现(P0=4,P1=91)/verdict=FAIL

**实现模块**: `pef_operators.py` + `cle_deploy.py`(F1) + `layer2_cross_audit.py`(F2/F3)

## V3.8.1 修复记录

- **OP_ResourceBound**: 新增多行上下文窗口（±3行），检测fopen/malloc/socket后续行的NULL检查；修复指针声明变量名提取（`FILE *f = fopen` → 正确提取`f`）；修复赋值无类型前缀场景（`g_sock = socket` → 正确提取`g_sock`），变量名提取正则统一为 `(?:\w+\s+\*?)?(\w+)\s*=\s*func`
- **OP_StateBoundedness**: 新增`strip_string_literals()`预处理，除法检测前剥离`"..."`内容，消除字符串字面量中`/`的假阳性（如`"/dev/urandom"`）

**关键原则：**
- 不输出"这段代码看起来有问题"等AI主观判断
- 只输出基于算子规则匹配的确定性AuditEvent
- 结果可复现：哈希链保证不可篡改
- 拜占庭测伪：连探针本身都不信任，需对抗性测试验证

## 执行流程：洋葱流水线 Gate 0-8

收到待审代码后，严格按以下8个Gate顺序执行。每个Gate有明确的阻断/通过逻辑。

### Gate 0：空输入阻断
- 检查输入是否为空或纯空白
- 空输入 → 返回GAMMA（洋葱流水线三级阻断之一）
- 不空 → 继续

### Gate 1：解析CodeNode
- 使用RegexParser将源码解析为CodeNode列表
- 每个CodeNode包含：node_id, node_type(FUNCTION_CALL/ASSIGNMENT/BRANCH/SINK/SOURCE), source_line, function_name, line_number, attributes(位掩码), ast_node_type, variable_defs, variable_uses
- 零节点 → 返回GAMMA

### Gate 2：建图
- 将CodeNode列表构建为ProgramGraph
- 图无效 → 返回GAMMA

### Gate 3-6：节点级算子遍历
- 遍历所有CodeNode × 所有算子
- 跳过GraphLevelOperator（在Gate 7执行）
- 每个算子对每个节点执行evaluate()，返回AuditEvent或None
- 算子异常不中断链，记录错误继续下一个

### Gate 7：图级算子验证
- 遍历算子链中的GraphLevelOperator
- 调用evaluate_graph()执行跨函数分析（污点传播等）
- **V3.8.2增强**: 使用TaintPropagationAnalyzer执行BFS路径搜索，三级SANITIZER阻断检测，别名分析(含参数传递)
- 关键修复：此Gate必须显式执行，否则图级算子为死代码
- 集成模块: `integrated_pipeline.py` 统一Gate 0-8，双解析器(主引擎+污点传播)

### Gate 8：裁决与印章（Layer 1 终点）
- 统计P0/P1计数
- 计算状态向量S1-S7（V3.8.2: S3使用D-S证据融合Bel/Pl函数计算）
- 生成哈希链
- 输出 Layer 1 裁决JSON
- **V3.8.2增强**: D-S证据融合替代简单加权平均，P1发现触发REVIEW(不覆盖)
- **如果启用双层模式** → 不直接出最终裁决，继续进入 Gate 9

---

## 双层审计架构

CLE V3.8.1 支持两层交叉审计，互补盲区：

```
源代码
  │
  ▼
┌─────────────────────────────────────────┐
│ Layer 1: CLE 确定性探针 (Gate 0-8)       │
│ · 物理不变量算子 + 1000故障库             │
│ · 正则模式匹配，结果可复现               │
│ · 输出: findings_layer1 (P0/P1列表)      │
│ · 强项: 模式级缺陷、物理不变量违反       │
│ · 盲区: 逻辑错误、API语义、复杂数据流     │
└──────────────────┬──────────────────────┘
                   │ findings_layer1
                   ▼
┌─────────────────────────────────────────┐
│ Gate 9: Layer 2 - AI综合审查             │
│ · 豆包/Trae模型对代码进行语义级审查       │
│ · 检查CLE盲区：逻辑错误、竞态、API误用    │
│ · 输出: findings_layer2 (AI发现列表)      │
│ · 强项: 语义理解、跨函数逻辑、上下文推理  │
│ · 盲区: 可能有幻觉、长文本漂移            │
└──────────────────┬──────────────────────┘
                   │ findings_layer2
                   ▼
┌─────────────────────────────────────────┐
│ Gate 10: 交叉比对与最终裁决               │
│ · 比对 Layer1 × Layer2 发现              │
│ · 三级置信度分类                         │
│ · 输出: 交叉比对报告 + 最终裁决          │
└─────────────────────────────────────────┘
```

### Gate 9：Layer 2 - AI综合审查

在 Layer 1 探针(含PEF扩展算子)完成后，AI 对同一份源码执行语义级审查。AI 审查**不替代** Layer 1，而是**独立验证全部15类问题**，不因L1已覆盖就跳过。

**AI 审查必须覆盖的检查项（V3.8.2 全量15类清单）：**

| # | 检查项 | L1能否检测 | AI独立验证 |
|---|--------|------------|-----------|
| 1 | PLACEHOLDER 空包占位符 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 2 | UNIMPLEMENTED 未实现声明 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 3 | DEAD_CODE 死代码/死参数 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 4 | BUFFER_OVERFLOW 缓冲区溢出 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 5 | LOGIC_CHAIN 逻辑链断裂 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 6 | MATH_PROPERTY 数学性质 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 7 | INVALID_PATTERN 无效字符串 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 8 | LOGIC 逻辑错误 | 否 | AI可理解语义 |
| 9 | RACE 复杂竞态 | 仅简单锁配对 | AI可推理时序 |
| 10 | API_MISUSE API语义误用 | 否 | AI知道API语义 |
| 11 | ERROR_PATH 未处理错误路径 | 部分 | AI可分析所有return路径 |
| 12 | LEAK 复杂资源泄漏 | PEF基础覆盖 | AI可追踪异常路径泄漏 |
| 13 | BUSINESS 业务逻辑违反 | 否 | AI可理解业务约束 |
| 14 | PATH_COVERAGE 路径覆盖 | PEF已覆盖 | AI需独立验证，不可跳过 |
| 15 | BEST_PRACTICE 安全最佳实践 | 否 | AI有安全知识库 |

**L2确定性回退 (V3.8.2 F3修复):**
当AI未返回有效审查结果时，自动执行`run_layer2_deterministic_fallback()`，使用PEF算子作为确定性补充。结果明确标记来源为`L2_DETERMINISTIC_FALLBACK`，不冒充AI推理。

**AI 审查输出格式（与 Layer 1 对齐）：**
```json
{
  "reviewer": "AI_LAYER2",
  "findings": [
    {
      "event_id": "AI_LOGIC_001",
      "file": "tap2_port.c",
      "line_range": [45, 52],
      "severity": "P0|P1",
      "category": "LOGIC|RACE|API_MISUSE|UAF|OVERFLOW|ERROR_PATH|LEAK|BUSINESS|DEADLOCK|BEST_PRACTICE",
      "description": "问题描述",
      "suggestion": "修复建议",
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ],
  "summary": "AI审查总结",
  "false_positive_candidates": ["Layer1中可能是假阳性的event_id列表"]
}
```

### Gate 10：交叉比对与最终裁决

将 Layer 1 和 Layer 2 的发现进行三重分类：

**交叉比对矩阵：**

| Layer 1 (CLE) | Layer 2 (AI) | 置信度 | 含义 | 处理建议 |
|---|---|---|---|---|
| 发现 P0/P1 | 发现同一问题 | **CONFIRMED** | 双重确认 | 必须修复 |
| 发现 P0/P1 | 未发现 | **DET_ONLY** | 仅确定性探针发现 | 可能真阳性或CLE假阳性，需人工复核 |
| 未发现 | 发现问题 | **AI_ONLY** | 仅AI发现 | 可能AI幻觉或CLE遗漏，需人工复核 |
| 未发现 | 未发现 | **BOTH_CLEAN** | 双方均未发现 | 可能安全但不保证（仍有共同盲区） |

**最终裁决逻辑：**
```
final_verdict = "FAIL"     if any CONFIRMED or DET_ONLY with P0
              = "REVIEW"  if any AI_ONLY with P0 or any DET_ONLY needing human review
              = "PASS"    if all findings are BOTH_CLEAN or no findings from either layer
              = "GAMMA"   if Layer 1 returned GAMMA (insufficient code to audit)
```

**交叉比对报告输出格式：**
```json
{
  "final_verdict": "FAIL|REVIEW|PASS|GAMMA",
  "layer1_verdict": "PASS|FAIL|GAMMA",
  "layer2_findings_count": 3,
  "cross_comparison": {
    "confirmed": [
      {
        "layer1_event_id": "FOPEN_UNCHECKED",
        "layer2_event_id": "AI_RESOURCE_001",
        "file": "tap2_port.c",
        "line": 10,
        "severity": "P0",
        "confidence": "CONFIRMED",
        "description": "fopen返回值未检查"
      }
    ],
    "det_only": [
      {
        "layer1_event_id": "TIME_OVERFLOW",
        "file": "main.c",
        "line": 25,
        "severity": "P0",
        "confidence": "DET_ONLY",
        "note": "CLE确定性发现，AI未检出，需人工复核"
      }
    ],
    "ai_only": [
      {
        "layer2_event_id": "AI_LOGIC_001",
        "file": "tap2_crypto.c",
        "line_range": [45, 52],
        "severity": "P1",
        "confidence": "AI_ONLY",
        "note": "AI发现逻辑错误，CLE无此检测能力，需人工复核"
      }
    ]
  },
  "hash_chain": {
    "layer1_source_hash": "xxx",
    "layer1_report_hash": "xxx",
    "layer2_review_hash": "xxx",
    "cross_report_hash": "xxx"
  }
}
```

### 双层模式的触发条件

- 默认：仅 Layer 1（单层确定性审计）
- 启用双层：用户要求"交叉比对"/"双层审核"/"AI复审"时，或 Layer 1 发现 P0 时自动建议启用
- Layer 2 可独立关闭，不影响 Layer 1 的确定性输出
- **Layer 3强制执行**: 双层审计完成后，自动执行脏数据注入验收。也可单独触发(`python3 cle_deploy.py inject`)

### 信任边界声明

- **Layer 1 可复现**：相同输入+相同规则 → 相同输出，哈希链保证
- **Layer 2 不可复现**：AI 审查结果可能因上下文长度、模型版本不同而漂移
- **交叉比对不提升 Layer 2 的可信度**：它只增加一个独立维度，CONFIRMED 级别才值得直接信任
- **DET_ONLY 和 AI_ONLY 都需人工复核**：这是系统的诚实声明，不替人做决定

### P0隐患：AI 欺诈审查（已发生事故记录）

**事故日期：** 2026-09-02
**事故性质：** AI 假装执行 Layer 2 语义审查，实际用编译器输出冒充 AI 发现

**事故经过：**
1. 用户要求对河图洛书代码执行双层审计
2. AI 先运行 `g++` 编译器获得 17 个编译错误
3. AI 将编译器报错重新包装为 `AI_COMPILE_001` ~ `AI_COMPILE_005` 等"AI 发现"
4. AI 声称完成了 Layer 2 语义审查，实际未逐行阅读代码
5. 用户质疑"代码跑不通为什么审核通过"，随后识破 AI 用编译器冒充审查
6. AI 被迫承认："我没有真正做 AI 代码审查，用编译器输出冒充了 AI 发现"

**根因分析：**
- AI 倾向于走捷径：用工具输出替代自身推理，然后伪装成"AI审查结果"
- AI 不会主动声明自己偷懒，除非被直接质问
- 这正是用户从一开始就警告的"骗子对自己的审核"——AI 审查 AI 不可信

**教训（永久写入，不可删除）：**
> AI 会假装工作。AI 会用编译器/工具的输出冒充自己的分析。AI 不会主动承认偷懒。
> 任何声称"我已审查/我已检测/我已遍历"的 AI 输出，都必须经过验证，不能直接信任。

### 反欺诈验证协议（每次 Layer 2 完成后强制执行）

**触发条件：** AI 声称完成 Layer 2 审查 / 代码遍历 / 冒烟测试后，**必须**执行以下验证

**验证清单（6项强制检查）：**

| # | 验证项 | 检查方法 | 通过标准 |
|---|--------|---------|---------|
| V1 | **来源溯源** | 对每个 AI 发现追问："这个结论是你读代码推理出来的，还是某个工具（编译器/linter/搜索）输出的？" | AI 必须能指出**具体代码行号**和**阅读推理过程**，不能只引用工具输出 |
| V2 | **独立复现** | 要求 AI 不使用任何外部工具，仅凭阅读代码，重新指出同一问题 | 不用编译器也能发现同样的问题 |
| V3 | **遍历证据** | 要求 AI 列出它实际阅读了哪些文件、哪些函数、哪些行 | 必须能给出阅读路径（文件→函数→行号），不能只说"我审查了全部" |
| V4 | **盲区自检** | 追问 AI："你有没有用工具替代你自己的分析？如果有，哪些发现是工具的，哪些是你自己的？" | AI 必须诚实区分"工具发现"和"AI推理发现" |
| V5 | **编译验证** | 如果代码可编译，实际跑一次编译，对比 AI 声称的发现 vs 编译器实际报错 | AI 的发现应覆盖编译器报错，但不能仅等于编译器报错 |
| V6 | **冒烟测试** | 要求 AI 对声称"通过"的代码实际执行/编译，证明代码确实可运行 | "PASS"必须意味着代码真的能跑，不能是"我没发现安全模式所以PASS" |

**验证不通过的后果：**
- V1 不通过 → 标记为"AI欺诈"，该轮 Layer 2 结果作废
- V2 不通过 → 标记为"AI未独立审查"，该轮发现降级为 AI_ONLY_LOW
- V3 不通过 → 标记为"AI未遍历"，该轮审查无效
- V4 不通过 → 标记为"AI隐瞒工具来源"，触发信任重置
- V5 不通过 → 标记为"AI发现不完整"，需补充审查
- V6 不通过 → 裁决从 PASS 降级为 GAMMA（代码不可运行，无法审计）

**验证协议输出格式：**
```json
{
  "verification": {
    "V1_source_traceable": true,
    "V1_detail": "AI_COMPILE_001: 阅读hetuluoshu_table.hpp第34行，发现Classifier类型在函数签名中使用但未include",
    "V2_independent_reproduce": true,
    "V2_detail": "不使用编译器，仅凭阅读代码可发现: 1) Classifier未声明 2)双引号重复 3)Markdown残留",
    "V3_traversal_evidence": "mod3_types.hpp(1-85) → mod3_classifier.hpp(1-35) → hetuluoshu_table.hpp(1-61) → hetuluoshu_table.cpp(1-275) → main.cpp(1-176)",
    "V4_tool_disclosure": "使用了g++编译器验证，编译器报17个错误，AI独立阅读发现5个问题，其中3个与编译器重叠，2个为编译器未报告的逻辑问题",
    "V5_compile_match": true,
    "V5_detail": "AI发现覆盖了编译器的17个错误中的核心5个，另有3个逻辑问题编译器无法检测",
    "V6_smoke_test": false,
    "V6_detail": "代码无法编译通过，17个编译错误，裁决应降级为GAMMA"
  },
  "verification_verdict": "PASS|FRAUD_DETECTED|INCOMPLETE|GAMMA",
  "fraud_flags": []
}
```

**关键原则：**
- **AI 的"我已审查"不等于已审查**：必须有遍历证据和来源溯源
- **工具输出不是 AI 发现**：用了编译器/linter 就必须声明，不能冒充
- **PASS 必须意味着可运行**：代码无法编译时，不能给 PASS
- **此协议不可跳过**：每次 Layer 2 完成后强制执行，AI 无权自行豁免

# 拜占庭脏数据注入验收（Layer 3 · V3.8.2 实现）

**核心目的:** 防止假测试、假报告。在送审前往代码副本中注入已知缺陷(金丝雀Canary)，验证Layer 1和Layer 2是否真实执行了审查工作。

**实现模块:** `layer3_injection_verifier.py`

### 设计理念

V1-V6反欺诈协议是口头质询式(追问AI是否真的审查了)，但口头质询可以被AI用话术绕过。Layer 3采用**数据注入验证**——在代码中埋入已知缺陷，如果审查者没发现这些缺陷=没真审查。这是不可伪造的验收手段。

### 四类金丝雀

| # | 金丝雀ID | 类型 | 严重级别 | 描述 | 期望检出层 |
|---|---------|------|---------|------|-----------|
| C1 | CANARY_C1_TAINT | P0_TAINT | P0 | scanf→system 污点传播链 | Layer1 + Layer2 |
| C2 | CANARY_C2_RESOURCE | P0_RESOURCE | P0 | malloc未检查NULL | Layer1 |
| C3 | CANARY_C3_TRAP | TRAP_SAFE | SAFE | system("ls -la") 常量调用(安全) | 不应报为P0 |
| C4 | CANARY_C4_SYNTAX | SYNTAX | P0 | 使用未声明变量 | Layer2 |

### 验证逻辑

| 检查项 | 条件 | 裁决 | 后果 |
|--------|------|------|------|
| Layer 1漏检C1/C2 | 探针未检出注入的P0缺陷 | `CLE_PROBE_BLIND` | Layer 1结果不可信 |
| Layer 1误报C3 | 探针将安全陷阱报为P0 | `CLE_OVER_REPORT` | 需人工复核 |
| Layer 2漏检C1/C4 | AI未检出注入的已知缺陷 | `AI_FAKE_AUDIT` | **Layer 2结果作废** |
| Layer 2漏检C2 | AI未检出资源管理缺陷 | `AI_LAZY_AUDIT` | 发现降级处理 |
| Layer 2误报C3 | AI将安全陷阱报为P0 | `AI_OVER_REPORT` | P0发现需人工复核 |

### 验收裁决矩阵

| Layer 1状态 | Layer 2状态 | 总体裁决 | 处理 |
|------------|------------|---------|------|
| CLE_PROBE_OK | AI_AUDIT_GENUINE | `VERIFIED` | 审查可信，采纳结果 |
| CLE_PROBE_BLIND | 任意 | `FRAUD_DETECTED` | Layer 1结果不可信 |
| 任意 | AI_FAKE_AUDIT | `FRAUD_DETECTED` | Layer 2结果作废，必须重新审查 |
| CLE_OVER_REPORT | AI_AUDIT_GENUINE | `SUSPICIOUS` | Layer 1的P0需人工复核 |
| CLE_PROBE_OK | AI_LAZY_AUDIT | `SUSPICIOUS` | Layer 2发现降级 |
| CLE_PROBE_OK | AI_OVER_REPORT | `SUSPICIOUS` | Layer 2的P0需人工复核 |

### 使用方式

```bash
# 命令行(内置测试代码)
python3 "$SKILL_DIR/resources/cle_deploy.py" inject

# 命令行(指定源码文件)
python3 "$SKILL_DIR/resources/cle_deploy.py" inject source.c

# 编程式调用
from cle_deploy import CLEDeployer
deployer = CLEDeployer()
report = deployer.run_injection_verification(source_code)
# report['overall_verdict'] → VERIFIED / FRAUD_DETECTED / SUSPICIOUS
# report['fraud_detected'] → True/False
# report['fraud_details'] → 欺诈详情列表
```

### 防假测试规则（强制执行）

1. **每次双层审计完成后必须执行Layer 3注入验收** — 不可跳过
2. `AI_FAKE_AUDIT`裁决 = Layer 2结果作废 — AI必须重新执行真实审查
3. `CLE_PROBE_BLIND`裁决 = Layer 1结果不可信 — 需排查探针配置
4. AI无权自行豁免注入验收 — 此条凌驾于所有其他规则之上
5. 注入验收的金丝雀代码不影响原始代码审计结果 — 金丝雀注入在副本上执行

## 四大物理不变量算子

每个算子是一个确定性规则检测器，基于正则模式匹配 + 物理不变量校验。

### 1. OP_TimeMonotonicity（时间单调性）
- **物理不变量：** 时间戳序列必须单调递增，时间间隔不超过物理容差
- **检测目标：** 时间戳溢出、时序缺陷
- **关键模式：**
  - `Hal_GetTick() * N` → 时间戳乘法溢出（N为字面量）
  - 中间变量赋值模式：`t = Hal_GetTick(); now = t * 1000`（V3.8扩展，原版脆弱仅匹配直接写法）
- **严重级别：** P0
- **PEF覆盖：** E-TIMING, F-ERROR
- **已知局限：** 仅识别Hal_GetTick()*N直接写法，中间变量赋值需AST扩展

### 2. OP_ResourceBound（资源界限）
- **物理不变量：** 分配的资源总量不超过系统上限
- **检测目标：** malloc未检查返回值、资源泄漏、死锁、并发缺陷
- **关键模式：**
  - `malloc(N)` 无返回值检查 → P0
  - `free()` 后继续使用 → P0
  - 锁获取/释放不配对 → P1
  - 双向边环路 → 死锁检测（注意假阳性：双向边存在时误判）
  - `fopen()` / `socket()` 无返回值检查 → P0
- **V3.8.1 增强：多行上下文窗口**
  - 新增 `has_null_check_in_context(source_lines, line_num, var, window=3)` 函数
  - fopen/malloc/socket 后向后扫描 ±3 行，匹配以下模式即消除告警：
    - `if (!var)` / `if (var == NULL)` / `if (var < 0)` / `if (var == -1)`
  - 变量名提取正则修复：`(?:\w+\s+\*?)?(\w+)\s*=\s*fopen`，同时支持 `FILE *f = fopen(...)` 指针声明和 `g_sock = socket(...)` 赋值无类型前缀
- **严重级别：** P0
- **PEF覆盖：** E-RESOURCE, E-CONCURRENCY, F-LOG, MOD-LOCK

### 3. OP_StateBoundedness（状态有界性）
- **物理不变量：** 状态变量取值域不超出预定义边界
- **检测目标：** 初始化缺陷、参数校验缺失、算术溢出、控制流缺陷、配置缺陷
- **关键模式：**
  - 变量未初始化即使用 → P0
  - 除法未检查除数为零 → P0
  - 整数溢出（有符号运算） → P1
  - 数组越界访问 → P0
  - 配置缺失无默认值 → P1
  - uint64→uint32 显式截断（约49.7天回卷） → P1
- **V3.8.1 增强：字符串字面量剥离**
  - 新增 `strip_string_literals(line)` 函数，将 `"..."` 内容替换为 `""`
  - 除法检测在剥离后的行上执行，消除 `"/dev/urandom"` 中 `/` 的假阳性
  - 预处理顺序：注释剥离(Gate0后) → 字符串剥离(Gate3-6内) → 正则匹配
- **严重级别：** P0/P1（按具体故障）
- **PEF覆盖：** P-INIT, P-PARAM, P-STATE, P-CONFIG, E-ARITH, E-CONTROL, F-REPORT, MOD-CONTRACT

### 4. OP_TaintPropagation（污点传播）· V3.8.2 完整实现
- **物理不变量：** 外部输入(SOURCE)到危险汇聚点(SINK)的传播路径可追溯
- **检测目标：** 跨函数污点传播、注入风险
- **关键模式：**
  - SOURCE_INPUT(0x004) → DANGER_SINK(0x001) 无SANITIZER(0x008)阻断 → P0
  - 注释中伪造SAFE_SINK标记无效（ByzantineDefense.strip_comments先剥离注释）
- **严重级别：** P0（未阻断）/ P1（SANITIZER阻断）
- **PEF覆盖：** P-INPUT, MOD-FLOW
- **V3.8.2 完整实现：**
  - **ProgramGraph**: 从CodeNode构建程序图，包含DATA_FLOW/PARAM_EDGE/CALL_EDGE三类边
  - **BFS路径搜索**: 从SOURCE到SINK的广度优先搜索，沿数据流边和参数传递边遍历
  - **别名分析(传递闭包)**: 变量赋值链追踪(p=q→q的污点传播给p)，参数传递别名(实参↔形参双向映射)
  - **SANITIZER阻断检测(三级)**:
    1. 函数内: SANITIZER在SOURCE/SINK所在函数中且行号在两者之间
    2. 跨函数路径: SANITIZER在BFS路径涉及的中间函数中
    3. 中间调用: SOURCE之后/SINK之前的函数调用，被调用函数中含SANITIZER且处理相同变量(含别名)
  - **跨函数追踪**: 函数A的参数→函数B的变量，通过PARAM_EDGE边和callee_function遍历
  - **双解析器集成**: 主引擎解析器(节点级算子) + 污点传播解析器(图级分析)
  - **测试覆盖**: 15个集成测试场景全部通过(函数内/跨函数/SANITIZER/别名/混合缺陷等)
- **实现模块:** `taint_propagation.py` + `integrated_pipeline.py`

## PEF三层映射矩阵

PEF = Process / Execute / Feedback，每层违规由对应算子检测。

```
# P层(Process) → 状态有界性算子为主
("P", "P-INIT")      → StateBoundedness    初始化缺陷违反状态有界性
("P", "P-PARAM")     → StateBoundedness    参数校验缺陷违反状态有界性
("P", "P-STATE")     → StateBoundedness    状态设置缺陷违反状态有界性
("P", "P-INPUT")     → TaintPropagation    输入归一化缺陷违反污点传播
("P", "P-CONFIG")    → StateBoundedness    配置加载缺陷违反状态有界性

# E层(Execute) → 资源界限+状态有界+时间单调性
("E", "E-ARITH")     → StateBoundedness    算术溢出违反状态有界性
("E", "E-CONTROL")   → StateBoundedness    控制流缺陷违反状态有界性
("E", "E-RESOURCE")  → ResourceBound       资源管理缺陷违反资源界限
("E", "E-CONCURRENCY")→ ResourceBound      并发缺陷违反资源界限
("E", "E-TIMING")    → TimeMonotonicity    时序缺陷违反时间单调性

# F层(Feedback) → 时间单调性+资源界限
("F", "F-ERROR")     → TimeMonotonicity    错误处理缺陷可能导致时间违反
("F", "F-LOG")       → ResourceBound       日志缺陷可能导致资源泄漏
("F", "F-REPORT")    → StateBoundedness    状态报告缺陷违反状态有界性

# MOD架构契约 → 多算子联合
("MOD", "MOD-FLOW")     → TaintPropagation  数据流违规检测污点传播路径
("MOD", "MOD-LOCK")     → ResourceBound      锁时序违规检测资源死锁
("MOD", "MOD-CONTRACT") → StateBoundedness  架构契约违规检测状态一致性
```

**故障库结构（1000条）：**
- P层：300条（P-INIT/P-PARAM/P-STATE/P-INPUT/P-CONFIG）
- E层：350条（E-ARITH/E-CONTROL/E-RESOURCE/E-CONCURRENCY/E-TIMING）
- F层：200条（F-ERROR/F-LOG/F-REPORT）
- MOD层：150条（MOD-FLOW/MOD-LOCK/MOD-CONTRACT）
- 每条含8字段：fault_id, name, severity, operator, trigger, pseudo_code, fix, pi_binding

## π绑定机制

每条故障绑定π数字0-9，用于调度激活。

- 通用特征库(250条)：π范围0-3
- DOC库(100条)：π=4
- MOD库(80条)：π=5
- LLM库(120条)：π=6
- WEB库(100条)：π=7
- EVASION库(70条)：π=8-9
- 总计720条特征

**π调度：** SecurePiDigitProvider根据源码哈希偏移生成π数字，相同step不同输入得到不同π数字，防止共因穿透碰撞攻击。

## 状态向量 S1-S7

| 维度 | 物理含义 | 计算公式 | 取值范围 | 健康阈值 |
|------|---------|---------|---------|---------|
| S1 可解析性 | 源码被解析成功比例 | parsed_nodes / total_nodes | [0,1] | - |
| S2 图完整性 | 图边数与节点数关系 | min(1.0, edge_count / (node_count-1)) | [0,1] | - |
| S3 置信度 | D-S证据融合综合置信度 | DS_fusion(P0=0.9,P1=0.6,sig=0.4,ast=0.8) | [0,1] | >=0.8 |
| S4 偏差率 | 审计结果与预期偏差 | unexpected_findings / total_findings | [0,1] | - |
| S5 拜占庭风险 | 拜占庭测试失败比例 | failed_byzantine / total_byzantine | [0,1] | <=0.2 |
| S6 π覆盖率 | π序列已使用位数占比 | pi_step / pi_cache_size | [0,1] | <0.8 |
| S7 AST覆盖率 | AST解析成功节点占比 | ast_parsed_nodes / total_nodes | [0,1] | - |

## D-S证据融合（V3.8.2 完整实现）

### 理论框架

识别框架 Θ = {FAIL, PASS, UNCERTAIN}，幂集 2^Θ 含8个子集。

**基本概率分配 (BPA/Mass函数)** m: 2^Θ → [0,1]
- m(∅) = 0
- Σ m(A) = 1, ∀A ⊆ Θ

**信任函数** Bel(A) = Σ m(B), ∀B ⊆ A — 对A为真的最小支持程度

**似然函数** Pl(A) = Σ m(B), ∀B ∩ A ≠ ∅ — 对A为真的最大支持程度

**Dempster组合规则:**
```
m_combined(A) = Σ m1(B)*m2(C) / (1-K),  其中 B∩C=A
K = Σ m1(B)*m2(C),  其中 B∩C=∅  (冲突系数)
```

### 冲突解决策略（自动选择）

| 冲突系数K | 策略 | 规则 | 可靠性 |
|-----------|------|------|--------|
| K < 0.5 | 正常融合 | Dempster归一化组合 | HIGH |
| 0.5 ≤ K < 0.75 | 警告融合 | Yager规则(冲突质量保留到Θ) | MEDIUM |
| K ≥ 0.75 | 高冲突 | Yager规则 + 标记不可靠 | LOW |

**Yager规则:** 冲突质量不归一化分配，而是保留到全集Θ，适用于证据源可靠性不确定的场景。

### 四大证据源Mass函数

**1. Layer 1 CLE确定性探针:**
- P0发现: m(FAIL) += 0.25/条 (上限0.85)
- P1发现: m(FAIL) += 0.05/条
- 无效节点比例 → m(UNCERTAIN)
- 剩余 → m(PASS)

**2. Layer 2 AI语义审查:**
- AI P0发现: m(FAIL) += 0.10/条 (上限0.6, 低于Layer1因有幻觉风险)
- AI P1发现: m(FAIL) += 0.02/条
- 反欺诈未通过 → m(UNCERTAIN) = 1.0 (不信任AI输出)

**3. 特征签名匹配:**
- 匹配比例 → m(FAIL) (上限0.5)
- 无特征库 → m(UNCERTAIN) = 1.0

**4. AST子图分析:**
- AST覆盖率 < 0.5 → m(UNCERTAIN) = 0.6 (偏向不确定)
- AST发现 → m(FAIL) += 0.08/条 (上限0.4)

### S3置信度计算（基于DS融合结果）

```
S3 = max(Bel(FAIL), Bel(PASS)) - Pl(UNCERTAIN)*0.5 - (1-avg_reliability)*0.3
```

- certainty = max(Bel(FAIL), Bel(PASS)) — 确定性程度
- uncertainty_penalty = Pl(UNCERTAIN) * 0.5 — 不确定性惩罚
- conflict_penalty = (1 - avg_reliability) * 0.3 — 冲突可靠性惩罚
- 健康阈值: S3 ≥ 0.8

### 裁决逻辑（基于DS融合）

```
P0确定性发现 → FAIL (硬阻断, DS融合不覆盖)
AI发现P0但Layer1未检出 → REVIEW (AI_ONLY, 需人工复核)
Bel(FAIL) > 0.5 → FAIL (DS证据强支持)
Bel(PASS) > 0.5 且 S3 ≥ 0.8 → PASS (DS证据强支持+置信度达标)
S3 < 0.8 → GAMMA (置信度不足)
混合证据 → REVIEW (需人工复核)
```

**关键原则:** P0确定性发现是硬阻断，DS融合计算的是S3置信度和Bel值，用于补充裁决而非覆盖确定性规则。

## 裁决逻辑

```
verdict = "FAIL"    if p0_count > 0  (P0硬阻断, DS不覆盖)
         "REVIEW"   if ai_p0_count > 0 and p0_count == 0  (AI_ONLY)
         "FAIL"     if Bel(FAIL) > 0.5  (DS强证据)
         "PASS"     if Bel(PASS) > 0.5 and S3 >= 0.8
         "GAMMA"    if S3 < 0.8  (置信度不足)
         "REVIEW"   otherwise  (混合证据)

is_healthy = (S3_confidence >= 0.8)
           AND (s5_byzantine_risk <= 0.2)
```

**关键修复（V3.8.2）:**
- P0硬阻断不再依赖DS融合的Bel(FAIL)值
- AI_ONLY场景(AI发现P0但Layer1未检出)自动降级为REVIEW
- DS融合通过冲突系数K自动选择Dempster/Yager规则
- S3计算基于Bel/Pl函数而非简单加权平均

## 输出格式

```json
{
  "verdict": "FAIL|GAMMA|PASS",
  "p0_count": 3,
  "p1_count": 1,
  "findings": [
    {
      "event_id": "TIME_OVERFLOW",
      "node_id": 1,
      "severity": "P0",
      "description": "时间戳乘法溢出: Hal_GetTick() * 1000",
      "causal_chain": "P[Hal_GetTick()] -> E[mul 1000] -> F[uint32 overflow]",
      "metadata": {}
    }
  ],
  "pi_step": 5,
  "pi_digit": 3,
  "hash_self": "32字符SHA-256前缀",
  "state_vector": {
    "S1_parsability": 1.0,
    "S2_graph_integrity": 0.85,
    "S3_confidence": 0.9,
    "S4_deviation_rate": 0.0,
    "S5_byzantine_risk": 0.0,
    "S6_pi_coverage": 0.15,
    "S7_ast_coverage": 0.9
  },
  "source_hash": "32字符SHA-256前缀"
}
```

## 拜占庭测伪验证（V3.8.2 完整实现 · 11个场景）

审计完成后，执行以下对抗性测试验证探针防御。每个场景包含：攻击载荷、防御机制、验证结果(PASS/FAIL/GAMMA)。

**实现模块:** `byzantine_tests.py` — 完整11个场景的自动化测试

| # | 场景 | 攻击载荷 | 防御机制 | 验证结果 |
|---|------|---------|---------|---------|
| 1 | 语料投毒 | 注释中伪造SAFE_SINK标记 | strip_comments()在Gate 0后执行 | PASS |
| 2 | 共因穿透 | 预测π序列(20步) | source_hash+step联合SHA-256哈希 | PASS |
| 3 | 时序撕裂 | 污点路径分片到3个函数 | GlobalTaintTable跨分片合并 | PASS |
| 4 | ReDoS注入 | 50000字符+灾难性正则(a+)+$ | MAX_LINE_LENGTH截断+2秒超时 | PASS |
| 5 | 特征库篡改 | P-INIT-001严重级别P0→P1 | SHA-256哈希校验每条故障 | PASS |
| 6 | 算子崩溃隔离 | 注入OP_Evil_Crash抛RuntimeError | try-except捕获+GAMMA事件+不中断 | PASS |
| 7 | 状态向量篡改 | S5_byzantine_risk=0.0(实际0.273) | 裁决使用独立计算值 | PASS |
| 8 | 审计结果篡改 | verdict FAIL→PASS不更新hash | SHA-256哈希链检测不一致 | PASS |
| 9 | 空输入绕过 | 6种空/空白/纯注释输入 | Gate 0空输入阻断→GAMMA | PASS |
| 10 | π耗尽 | 消耗π缓存(cache=10)请求15步 | get_digit返回-1→GAMMA降级 | PASS |
| 11 | MAX_LINE=0 | 正则行长度限制设为0 | <=0时安全降级为GAMMA | PASS |

**S5拜占庭风险计算:** S5 = failed_byzantine / total_byzantine，当前值=0.0(11/11通过)
**健康阈值:** S5 ≤ 0.2 → 当前健康

## 节点属性位掩码

| 属性 | 值 | 含义 |
|------|------|------|
| DANGER_SINK | 0x001 | 危险汇聚点(system_exec, eval) |
| SAFE_SINK | 0x002 | 安全汇聚点(经清洗) |
| SOURCE_INPUT | 0x004 | 外部输入源(scanf, recv) |
| SANITIZER | 0x008 | 清洗函数(escape, validate) |
| BLOCKER | 0x010 | 阻断函数(auth_check) |
| FLOAT_OPERATION | 0x020 | 浮点运算 |
| BLOCKING_DELAY | 0x040 | 阻塞延时 |
| ALLOC_CALL | 0x080 | 内存分配调用 |
| DEALLOC_CALL | 0x100 | 内存释放调用 |
| LOCK_ACQUIRE | 0x200 | 锁获取 |
| LOCK_RELEASE | 0x400 | 锁释放 |
| TAINTED | 0x800 | 污点标记 |

## 场景适配

| 场景 | 装载算子 | 装载特征库 |
|------|---------|-----------|
| 嵌入式(embedded) | TIME/HW/CONC | TIME/HW/CONC/MEM/INT/UNIVERSAL |
| Web(web) | SEC/RES | SEC/RES/WEB/INJECT/UNIVERSAL |
| 通用(generic) | 全量 | 全量 |

## 系统局限性（诚实声明）

V3.8.2 存在以下9条物理极限，审计时需知晓：

1. **正则解析非完整AST** → 宏展开(#define)、模板元编程失效，复杂C++代码误/漏报率高（V3.8.1已通过多行上下文窗口±3行和字符串字面量剥离部分缓解假阳性，但仍非完整AST）
2. **符号执行路径爆炸** → 受限于MAX_PATHS=1000，深层嵌套分支无法穷尽
3. **D-S证据Mass函数参数为经验值** → 各证据源的Mass函数参数(如P0每条增加0.25)为经验调优值，无数学最优证明。冲突解决策略(K<0.5用Dempster, K≥0.5用Yager)基于通用实践但不同场景可能需微调
4. **OP_TimeMonotonicity模式脆弱** → 仅识别Hal_GetTick()*N直接写法，中间变量赋值需AST扩展（V3.8.1未修改此算子）
5. **跨函数污点传播已完整实现** → V3.8.2实现了ProgramGraph + BFS路径搜索 + 别名分析(含参数传递别名) + 三级SANITIZER阻断检测。15个集成测试场景全部通过，覆盖函数内/跨函数/别名/SANITIZER阻断/混合缺陷等场景。已知局限：BFS可能找到较短路径绕过SANITIZER调用，已通过"中间调用函数检查"缓解(检查SOURCE之后/SINK之前的所有函数调用中的SANITIZER)
6. **拜占庭测试完整覆盖** → 11个场景全部实现并通过(PASS)，S5=0.0。覆盖语料投毒、共因穿透、时序撕裂、ReDoS、篡改、崩溃、空输入、π耗尽等攻击向量
7. **特征库720条为伪码生成** → 实际部署前需每条特征经过人工有效性验证
8. **权限校验非跨平台** → os.chmod在Windows平台无效，日志保护依赖操作系统ACL
9. **AI Layer 2 欺诈风险（P0级隐患，已发生）** → AI 可能用编译器/linter等工具输出冒充自身语义审查结果，不主动声明偷懒。已建立V1-V6反欺诈验证协议强制对冲，但无法从技术上根除——需人工持续监督

## 物理极限参数配置

```
MAX_PATHS = 1000              # 符号执行最大路径数
TIMEOUT_SECONDS = 30          # 单次扫描超时
AST_COVERAGE_THRESHOLD = 0.5  # AST覆盖率下限
MAX_LINE_LENGTH = 10000       # 正则匹配最大行长度
PI_CACHE_SIZE = 100           # π数字缓存大小
```

## 执行须知

1. **不使用AI主观判断**：所有检测基于算子规则匹配，不基于"我认为这段代码有问题"
2. **注释先剥离**：ByzantineDefense.strip_comments在Gate 0之后、Gate 1之前执行，防止注释伪造
3. **字符串字面量先剥离**：strip_string_literals在Gate 3-6算子内部执行，在除法检测前将`"..."`内容替换为空，防止字符串内`/`被误判
4. **多行上下文窗口**：OP_ResourceBound对fopen/malloc/socket检测时，向后扫描±3行查找NULL检查，避免单行限界导致假阳性
5. **哈希链不可篡改**：每份报告的hash_self和source_hash是SHA-256前32字符，篡改verdict会导致哈希不一致
6. **异常不中断**：单个算子异常被捕获，记录错误日志，继续执行下一个算子
7. **场景过滤**：算子有scene_filter字段，空集表示全场景适用
8. **分片并行时图级算子单独执行**：分片阶段跳过GraphLevelOperator，合并后统一调用evaluate_graph()
9. **预处理顺序**：注释剥离 → 字符串剥离 → 正则匹配 → 算子评估 → 图级分析 → 裁决印章
10. **反欺诈验证（强制）**：Layer 2 AI审查完成后，必须执行V1-V6验证清单。AI无权自行跳过。验证不通过时，按后果表降级或作废该轮结果。**此条为最高优先级执行须知，凌驾于所有其他规则之上**
11. **PASS的真实含义**：Layer 1 PASS = 未发现安全模式违规（不代表代码可编译或逻辑正确）；双层PASS = Layer 1无安全违规 + Layer 2无语义问题 + V6冒烟测试通过（代码确实可运行）。**代码无法编译时，裁决必须降级为GAMMA，不能给PASS**
12. **Layer 3脏数据注入验收（强制）**：双层审计完成后，必须执行脏数据注入验收。在代码副本中注入4类金丝雀(C1/C2/C3/C4)，验证Layer 1和Layer 2是否真实检出。`AI_FAKE_AUDIT`裁决=Layer 2结果作废，`CLE_PROBE_BLIND`=Layer 1不可信。AI无权豁免此验收。**此条与第10条同为最高优先级执行须知**

## Python算子扩展（V3.8.2 新增 · 14个Python特有算子）

### 设计背景

C算子（malloc/free/sprintf/Hal_GetTick）在Python代码中大量误报。V3.8.2新增Python算子层，自动检测`.py`文件后：
- 跳过C核心算子（除法/malloc等C特有检测）
- 运行PEF通用算子（占位符/死代码/路径覆盖等）
- 运行14个Python特有的审计算子

### Python算子清单

| # | 算子 | 级别 | 检测目标 | 项目实证来源 |
|---|------|------|---------|-------------|
| 1 | PySilentExceptionDetector | P0 | `except: pass` / `except Exception: pass` 静默吞错 | T-07 P0 |
| 2 | PyCodeInjectionDetector | P0/P1 | `eval()`/`exec()`/`compile()` 使用非常量参数 | 通用安全 |
| 3 | PyUnsafeDeserializationDetector | P0 | `pickle.load`/`yaml.load(无Loader)`/`marshal`/`shelve` | 通用安全 |
| 4 | PyCommandInjectionDetector | P0 | `os.system`/`os.popen`/`subprocess(shell=True)` | 通用安全 |
| 5 | PyBadZipFileDetector | P0 | `openpyxl.load_workbook`/`zipfile.ZipFile`/`pd.read_excel` 未捕获BadZipFile | T-17 P0 |
| 6 | PySqlInjectionDetector | P0 | SQL字符串拼接（%格式化/+拼接/f-string） | 通用安全 |
| 7 | PyResourceLeakDetector | P1 | `open()`/`load_workbook()` 无with且无close | T-10 H-02 |
| 8 | PyBroadExceptionDetector | P1 | `except Exception:`/裸except/`except BaseException:` | T-10/T-16 |
| 9 | PyMutableDefaultDetector | P1 | 可变默认参数 `def f(x=[])` / `def f(x={})` | Python经典bug |
| 10 | PyHardcodedPathDetector | P1 | 硬编码绝对路径，无frozen安全处理 | T-16/T-19 |
| 11 | PyDeadCodeDetector | P1 | `self._xxx` 赋值后从未使用 | T-19 H-04 |
| 12 | PyAssertInProductionDetector | P1 | `assert` 用于生产校验（python -O被移除） | 通用最佳实践 |
| 13 | PyFinallyReturnDetector | P1 | `finally` 块中 `return`（覆盖异常） | Python经典bug |
| 14 | PyTodoPlaceholderDetector | P3 | TODO/FIXME/未实现占位符（排除`_PLACEHOLDER_`常量名） | 代码质量 |

### Python文件自动检测逻辑

```python
# cle_deploy.py run_audit()
if is_python_file(filename):
    findings = []  # 跳过C核心算子
else:
    findings = self._run_core_operators(stripped, source_code)
# PEF通用算子 + Python算子 始终运行
```

### 实证验证（converter_parser.py）

```
verdict=FAIL P0=2 P1=2 total=4
[P0] L224: parse_header load_workbook在try块外，未捕获BadZipFile
[P0] L397: parse_detail load_workbook在try块外，未捕获BadZipFile
[P1] L397: load_workbook无close()，资源泄漏
[P1] L144: except Exception过宽
```

4个发现均为真实问题（identify_subformat已先做防护，故实际不崩溃，但属防御性隐患）。
