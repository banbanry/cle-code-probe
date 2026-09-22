#!/usr/bin/env python3

# Source: https://github.com/banbanry/cle-code-probe
# Author: banbanry (沈鹭) · 厦门恒元架构科技有限公司
# License: MIT
# PEF Architecture: https://github.com/banbanry/pef-architecture
# PEF ID: PEF0001 - CLE Code Probe (Deterministic Code Audit)

"""
CLE V3.8.2 PEF算子库扩展 — 13个E层算子（V3.9.2新增DangerousFunctionDetector+MallocNullCheckDetector）
从PEF算子库500+条中筛选适配，填补原始4大算子的检测盲区。V3.9.2新增gets危险函数检测和malloc NULL检查追踪。
P1阶段L6强化(Task6)：新增22个C/C++ F/E/MOD层高价值算子，可运行规则目录扩至~40条。
"""
import re
from typing import List, Dict
from cle_base_layer import AuditEvent, strip_c_comments

# ============================================================
# 第一批: 空包占位符/逻辑链断裂/死代码
# ============================================================

class PlaceholderDetector:
    """E033 Frama-C适配: 空包占位符检测"""
    PLACEHOLDER_PATTERNS = [
        (r'TODO|FIXME|HACK|XXX', 'TODO/FIXME占位符标记'),
        (r'暂不实现|待实现|not.implemented', '未实现占位符标记'),
        # 排除Python常量名 _PLACEHOLDER_xxx = '...'（这是正常的常量定义，不是未实现标记）
        (r'(?<!_)placeholder(?!_)|stub(?!\s*=)', '未实现占位符标记'),
    ]
    EMPTY_BODY_PATTERNS = [
        (r'\w+\s*\([^)]*\)\s*\{\s*\}', '空函数体(仅有花括号)'),
        (r'\w+\s*\([^)]*\)\s*\{\s*return\s+(?:true|false|0|1|nullptr|NULL)\s*;\s*\}', '仅返回常量的空函数'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        # 注释剥离前检测占位符
        for i, line in enumerate(lines):
            for pat, desc in self.PLACEHOLDER_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        'event_id': f'PEF_PLACEHOLDER_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PLACEHOLDER',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '实现该占位符标记的完整逻辑'
                    })
        # 空函数体检测
        for i, line in enumerate(lines):
            for pat, desc in self.EMPTY_BODY_PATTERNS:
                if re.search(pat, line.strip()):
                    findings.append({
                        'event_id': f'PEF_EMPTY_BODY_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PLACEHOLDER',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '补充函数体实现'
                    })
        return findings


class LogicChainVerifier:
    """E056 CEGAR适配: 逻辑链断裂检测"""
    RETURN_CHECK_PATTERNS = [
        (r'(\w+)\s*=\s*(?:load|init|configure|setup|create|open)\s*\(', 'load/init返回值未检查'),
        (r'(\w+)\s*=\s*(?:new\s+\w+)', 'new返回值未检查'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.RETURN_CHECK_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1)
                    # 检查后续3行是否有if检查
                    has_check = False
                    for j in range(i+1, min(i+4, len(lines))):
                        if re.search(rf'if\s*\(\s*!?\s*{re.escape(var)}\b', lines[j]):
                            has_check = True
                            break
                    if not has_check:
                        findings.append({
                            'event_id': f'PEF_LOGIC_CHAIN_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'LOGIC_CHAIN',
                            'description': f'{desc}: 变量{var}在第{i+1}行',
                            'suggestion': f'检查{var}的返回值是否有效'
                        })
        return findings


class DeadCodeDetector:
    """E034 Astree适配: 死代码检测"""
    DEAD_PARAM_PATTERNS = [
        (r'kd\s*=\s*0\.0|threshold\s*=\s*0\.0', '参数设为0.0导致路径失效'),
    ]
    UNREACHABLE_PATTERNS = [
        (r'return\s+[;\n]', 'return后不可达代码'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.DEAD_PARAM_PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'PEF_DEAD_CODE_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'DEAD_CODE',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查参数值是否合理'
                    })
        return findings


class MathPropertyVerifier:
    """E022 Z3 SMT适配: 数学性质检测"""
    NARROWING_PATTERNS = [
        (r'static_cast\s*<\s*(?:uint8_t|uint16_t|int8_t|int16_t)\s*>\s*\(', 'static_cast窄化转换'),
        (r'\b(?:int8_t|int16_t)\s+\w+\s*=\s*\w+\s*%', '取模可能碰撞窄类型'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.NARROWING_PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'PEF_MATH_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'MATH_PROPERTY',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查数值范围是否溢出'
                    })
        return findings


class StringLiteralValidator:
    """E040 UBSan适配: 字符串有效性检测"""
    INVALID_PATTERNS = [
        (r'\.find\s*\(\s*"NULL_check"', '搜索不存在的字符串"NULL_check"'),
        (r'\.find\s*\(\s*"null_check"', '搜索不存在的字符串"null_check"'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.INVALID_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        'event_id': f'PEF_INVALID_STR_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'INVALID_PATTERN',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查搜索字符串是否正确'
                    })
        return findings


class UnimplementedDeclDetector:
    """E035 CBMC适配: 未实现声明检测"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        # 检测.h中的函数声明
        decl_pattern = re.compile(r'(\w+)\s+(\w+)\s*\([^)]*\)\s*;')
        # 检测.cpp中的函数定义
        def_pattern = re.compile(r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{')

        declarations = set()
        for i, line in enumerate(lines):
            m = decl_pattern.search(line)
            if m and not line.strip().startswith('//'):
                declarations.add(m.group(2))

        definitions = set()
        for i, line in enumerate(lines):
            m = def_pattern.search(line)
            if m:
                definitions.add(m.group(2))

        unimplemented = declarations - definitions
        for name in unimplemented:
            findings.append({
                'event_id': f'PEF_UNIMPL_{name}',
                'line': 0, 'severity': 'P1',
                'category': 'UNIMPLEMENTED',
                'description': f'函数{name}已声明但未实现',
                'suggestion': f'实现函数{name}的定义'
            })
        return findings


# ============================================================
# 第二批: 内存安全/资源泄漏/路径覆盖
# ============================================================

class BufferOverflowDetector:
    """E039 ASan适配: 缓冲区溢出检测"""
    NPOS_RISK_PATTERN = re.compile(r'\.find\s*\([^)]+\)\s*;\s*\n\s*(\w+)\.substr\s*\(')
    UNSAFE_STR_OPS = [
        (r'strcpy\s*\(', 'strcpy无边界检查'),
        (r'sprintf\s*\(', 'sprintf无边界限制'),
        (r'strcat\s*\(', 'strcat无边界检查'),
    ]
    ARRAY_NO_BOUNDS = re.compile(r'\b(\w+)\s*\[\s*\w+\s*\]\s*[=;]')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            # find()返回npos后直接substr
            if '.find(' in line and 'npos' not in line:
                for j in range(i+1, min(i+3, len(lines))):
                    if '.substr(' in lines[j] and 'npos' not in lines[j]:
                        findings.append({
                            'event_id': f'BUF_NPOS_{i+1}',
                            'line': i+1, 'severity': 'P0',
                            'category': 'BUFFER_OVERFLOW',
                            'description': f'find()返回值未检查npos, 直接用于substr可能越界访问',
                            'suggestion': 'find()后检查 pos != string::npos 再使用substr'
                        })
                        break
            # 不安全的字符串操作
            for pat, desc in self.UNSAFE_STR_OPS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'BUF_UNSAFE_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'BUFFER_OVERFLOW',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '使用strncpy/snprintf等安全版本'
                    })
        return findings


class UninitMemoryDetector:
    """E041 MSan适配: 未初始化内存检测"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        decl_pattern = re.compile(r'\b(?:int|float|double|char|bool|auto)\s+(\w+)\s*;')
        for i, line in enumerate(lines):
            m = decl_pattern.search(line)
            if m:
                var = m.group(1)
                # 检查后续行是否有赋值
                has_init = False
                for j in range(i+1, min(i+5, len(lines))):
                    if re.search(rf'\b{re.escape(var)}\s*=', lines[j]):
                        has_init = True
                        break
                # 检查是否在同一行使用
                for j in range(i+1, min(i+3, len(lines))):
                    if re.search(rf'\b{re.escape(var)}\b', lines[j]) and '=' not in lines[j].split(var)[0]:
                        if not has_init:
                            findings.append({
                                'event_id': f'PEF_UNINIT_{i+1}',
                                'line': i+1, 'severity': 'P1',
                                'category': 'UNINIT_MEMORY',
                                'description': f'变量{var}声明后未初始化可能被使用',
                                'suggestion': f'声明{var}时赋予初始值'
                            })
                            break
        return findings


class ResourceLeakDetector:
    """E043 Valgrind适配: 资源泄漏检测"""
    FILE_OPEN_PATTERNS = [
        (r'(\w+)\s*=\s*fopen\s*\(', 'fopen'),
        (r'std::ifstream\s+(\w+)\s*\(', 'ifstream'),
    ]
    NEW_PATTERN = re.compile(r'new\s+\w+')
    DELETE_PATTERN = re.compile(r'delete\s+')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, label in self.FILE_OPEN_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1) if m.lastindex else ''
                    has_close = False
                    for j in range(i+1, len(lines)):
                        close_pat = rf'(?:fclose|close|\.close\s*\(\s*)\s*{re.escape(var)}' if var else r'(?:fclose|close|\.close\s*\()'
                        if re.search(close_pat, lines[j]):
                            has_close = True
                            break
                    if not has_close:
                        findings.append({
                            'event_id': f'PEF_LEAK_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'RESOURCE_LEAK',
                            'description': f'{label}打开后未见关闭',
                            'suggestion': f'确保在所有路径上关闭资源'
                        })
            # new without delete
            if self.NEW_PATTERN.search(line):
                has_delete = False
                for j in range(i+1, min(i+50, len(lines))):
                    if self.DELETE_PATTERN.search(lines[j]):
                        has_delete = True
                        break
                if not has_delete:
                    findings.append({
                        'event_id': f'PEF_NEW_LEAK_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'RESOURCE_LEAK',
                        'description': 'new分配后未见delete',
                        'suggestion': '确保释放动态分配的内存'
                    })
        return findings


class IntegerOverflowDetector:
    """E150 CBMC适配: 整数溢出检测"""
    MUL_PATTERNS = [
        (r'(\w+)\s*\*\s*(\d+)', '乘法运算无范围检查'),
    ]
    SHIFT_PATTERNS = [
        (r'<<\s*(\d+)', '左移可能丢失符号位'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.MUL_PATTERNS:
                if re.search(pat, line) and 'check' not in line.lower():
                    findings.append({
                        'event_id': f'PEF_INT_OVERFLOW_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'INTEGER_OVERFLOW',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '添加乘法结果的范围检查'
                    })
        return findings


class PathCoverageAnalyzer:
    """E049 KLEE适配: 路径覆盖检测"""
    ALWAYS_TRUE = re.compile(r'if\s*\(\s*(?:true|1|!0)\s*\)')
    ALWAYS_FALSE = re.compile(r'if\s*\(\s*(?:false|0)\s*\)')
    NO_DEFAULT = re.compile(r'switch\s*\(')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if self.ALWAYS_TRUE.search(line):
                findings.append({
                    'event_id': f'PEF_PATH_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PATH_COVERAGE',
                    'description': '恒真条件: 分支永远执行',
                    'suggestion': '检查条件是否应为变量'
                })
            if self.ALWAYS_FALSE.search(line):
                findings.append({
                    'event_id': f'PEF_PATH_DEAD_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PATH_COVERAGE',
                    'description': '恒假条件: 分支永不执行(死代码)',
                    'suggestion': '删除恒假分支或修正条件'
                })
            if self.NO_DEFAULT.search(line):
                # 检查后续是否有default
                has_default = False
                for j in range(i+1, min(i+30, len(lines))):
                    if 'default' in lines[j] and ('case' in lines[j] or ':' in lines[j]):
                        has_default = True
                        break
                    if '}' in lines[j] and 'case' not in lines[j]:
                        break
                if not has_default:
                    findings.append({
                        'event_id': f'PEF_SWITCH_DEFAULT_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PATH_COVERAGE',
                        'description': 'switch缺少default分支',
                        'suggestion': '添加default处理未知情况'
                    })
        return findings


class RaceConditionDetector:
    """E042 TSan适配: 数据竞争检测"""
    STATIC_VAR_PATTERNS = [
        (r'static\s+(?:int|float|double|char|bool|auto)\s+(\w+)', '静态变量无锁保护'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.STATIC_VAR_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1)
                    has_lock = False
                    for j in range(max(0, i-3), min(i+10, len(lines))):
                        if re.search(r'(?:lock|mutex|atomic|guard)', lines[j], re.IGNORECASE):
                            has_lock = True
                            break
                    if not has_lock:
                        findings.append({
                            'event_id': f'PEF_RACE_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'RACE_CONDITION',
                            'description': f'{desc}: 变量{var}',
                            'suggestion': '使用锁或atomic保护静态变量'
                        })
        return findings




class DangerousFunctionDetector:
    """E057 CWE适配: 危险函数检测（已被C11移除或存在已知安全缺陷）"""
    DANGEROUS_FUNCTIONS = [
        # 注意：strcpy/sprintf/strcat 已由 BufferOverflowDetector 覆盖，此处不重复检测
        # (pattern, severity, description, suggestion)
        (r'\bgets\s*\(', 'P0', 'gets()危险函数（已被C11标准移除，无边界检查，必然缓冲区溢出）', '使用fgets(buf, size, stdin)替代gets(buf)'),
        (r'\bvsprintf\s*\(', 'P1', 'vsprintf()无边界限制', '使用vsnprintf(buf, size, fmt, ap)替代'),
        (r'\bscanf\s*\([^)]*%s', 'P1', 'scanf()使用%s无宽度限制', '使用%Ns指定最大宽度（如%255s）'),
        (r'\bgetwd\s*\(', 'P1', 'getwd()危险函数（无边界检查）', '使用getcwd(buf, size)替代'),
        (r'\bcrypt\s*\(', 'P2', 'crypt()弱加密函数（已被标记为弃用）', '使用更安全的密码哈希算法（如bcrypt/Argon2）'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            # 跳过注释行（简单判断：行首//或在/* */内）
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            for pat, severity, desc, suggestion in self.DANGEROUS_FUNCTIONS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'DANGER_FUNC_{i+1}',
                        'line': i+1,
                        'severity': severity,
                        'category': 'DANGEROUS_FUNCTION',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': suggestion
                    })
        return findings


class MallocNullCheckDetector:
    """E058 CWE-476适配: malloc/calloc/realloc返回值NULL检查追踪"""
    ALLOC_FUNCTIONS = [
        (r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', 'malloc'),
        (r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?calloc\s*\(', 'calloc'),
        (r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(', 'realloc'),
    ]
    # NULL检查的模式：if (var == NULL) / if (!var) / if (NULL == var) / if (var == 0)
    NULL_CHECK_PATTERNS = [
        r'if\s*\(\s*!?\s*{var}\s*\)',
        r'if\s*\(\s*{var}\s*==\s*(?:NULL|nullptr|0)\s*\)',
        r'if\s*\(\s*(?:NULL|nullptr|0)\s*==\s*{var}\s*\)',
        r'if\s*\(\s*{var}\s*!=\s*(?:NULL|nullptr|0)\s*\)',
    ]
    CHECK_WINDOW = 5  # malloc后5行内检查NULL

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')

        for i, line in enumerate(lines):
            stripped = line.strip()
            # 跳过注释行
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue

            for alloc_pat, func_name in self.ALLOC_FUNCTIONS:
                m = re.search(alloc_pat, line)
                if m:
                    var = m.group(1)
                    # 检查后续CHECK_WINDOW行内是否有NULL检查
                    has_null_check = False
                    check_line = -1
                    for j in range(i+1, min(i+1+self.CHECK_WINDOW, len(lines))):
                        check_line_text = lines[j]
                        for null_pat in self.NULL_CHECK_PATTERNS:
                            if re.search(null_pat.format(var=re.escape(var)), check_line_text):
                                has_null_check = True
                                check_line = j+1
                                break
                        if has_null_check:
                            break

                    if not has_null_check:
                        findings.append({
                            'event_id': f'MALLOC_NULL_{i+1}',
                            'line': i+1,
                            'severity': 'P0',
                            'category': 'NULL_POINTER_DEREF',
                            'description': f'{func_name}()返回值未检查NULL: 变量{var}在第{i+1}行分配后{self.CHECK_WINDOW}行内无NULL检查，直接解引用可能导致空指针崩溃',
                            'suggestion': f'在{func_name}后立即检查 if ({var} == NULL) {{ /* 错误处理 */ }}',
                            'causal_chain': f'P[{func_name}] -> E[no NULL check] -> F[NULL pointer dereference]'
                        })
        return findings


# ============================================================
# P1阶段L6强化(Task6)：F/E/MOD 层高价值 C/C++ 算子
# 统一沿用 finding 字段: event_id/line/severity/category/description/suggestion
# 新类别: F_ERROR / E_CONTROL / E_RESOURCE / MOD_CONTRACT
# ============================================================

# ---------- F层 错误处理 (category=F_ERROR) ----------

class CReturnValueIgnoredDetector:
    """F层: 系统调用/文件IO返回值被忽略（独立语句形式调用）"""
    IGNORED_CALLS = (
        r'\b(?:fopen|open|fread|fwrite|read|write|close|remove|rename)\s*\([^)]*\)\s*;',
    )

    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pat in self.IGNORED_CALLS:
                if re.search(pat, line):
                    # 已是 if( 包裹则视为已检查
                    if re.search(r'if\s*\([^)]*\)', line) and re.search(pat, line[line.index('if'):] if 'if' in line else ''):
                        continue
                    findings.append({
                        'event_id': f'C_RET_IGNORE_{i+1}', 'line': i+1, 'severity': 'P2',
                        'category': 'F_ERROR',
                        'description': f'返回值被忽略: {stripped[:80]}',
                        'causal_chain': f'P[call] -> E[ignore return] -> F[错误不可见]',
                        'suggestion': '检查返回值，为负/异常时处理（如 if (fclose(fp) != 0) ...）',
                    })
                    break
        return findings


class CSensitiveInfoLogDetector:
    """F层: 敏感数据(密码/token/密钥)被打印或写入日志"""
    SENS = r'(?:password|passwd|pwd|secret|token|access[ _-]?key|api[ _-]?key)'
    LOG = r'(?:printf|fprintf|sprintf|snprintf|debug|trace|log|cout)\s*\('

    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            arg = re.search(rf'{self.LOG}[^)]*{self.SENS}', stripped, re.IGNORECASE)
            if arg and not re.search(r'(?:\*\*+|mask|hash|\.  \* +|redact)', stripped, re.IGNORECASE):
                findings.append({
                    'event_id': f'C_SENS_LOG_{i+1}', 'line': i+1, 'severity': 'P2',
                    'category': 'F_ERROR',
                    'description': f'敏感信息可能被写入日志/输出: {stripped[:80]}',
                    'causal_chain': f'P[sensitive] -> E[log/print] -> F[信息泄露]',
                    'suggestion': '不要直接输出敏感字段，改为打掩码或哈希',
                })
        return findings


class CSilentErrorBranchDetector:
    """F层: 空错误分支 if(err){ } 静默吞掉错误"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if re.search(r'if\s*\([^)]*\b(err|fail|ret|rc|result|status)\b[^)]*\)\s*\{\s*\}', stripped):
                findings.append({
                    'event_id': f'C_SILENT_ERR_{i+1}', 'line': i+1, 'severity': 'P1',
                    'category': 'F_ERROR',
                    'description': f'空错误分支，错误被静默丢弃: {stripped[:80]}',
                    'causal_chain': f'P[error] -> E[empty branch] -> F[状态不一致]',
                    'suggestion': '错误分支内应记录日志或做恢复/返回处理',
                })
        return findings


class CUnprotectedContinueDetector:
    """F层: 错误时仅 continue 跳过，未做任何处理"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.search(r'if\s*\([^)]*\b(err|fail|rc|ret|result)\b[^)]*\)\s*\{', stripped):
                # 单行块内含 continue
                if re.search(r'if\s*\([^)]*\b(err|fail|rc|ret|result)\b[^)]*\)\s*\{[^}]*\bcontinue\s*;', stripped):
                    findings.append({
                        'event_id': f'C_ERR_CONTINUE_{i+1}', 'line': i+1, 'severity': 'P1',
                        'category': 'F_ERROR',
                        'description': f'错误分支仅 continue 跳过，未记录/计数: {stripped[:80]}',
                        'causal_chain': f'P[error] -> E[continue] -> F[错误被静默跳过]',
                        'suggestion': 'continue 前做计数/日志/失败聚合处理',
                    })
                else:
                    # 多行: 向后找 continue
                    depth = 0
                    for j in range(i, min(i + 12, len(lines))):
                        depth += lines[j].count('{') - lines[j].count('}')
                        if re.search(r'\bcontinue\s*;', lines[j]) and depth <= 1:
                            findings.append({
                                'event_id': f'C_ERR_CONTINUE_{i+1}', 'line': i+1, 'severity': 'P1',
                                'category': 'F_ERROR',
                                'description': f'错误分支仅 continue 跳过，未记录/计数: {stripped[:60]}',
                                'causal_chain': f'P[error] -> E[continue] -> F[错误被静默跳过]',
                                'suggestion': 'continue 前做计数/日志/失败聚合处理',
                            })
                            break
                        if depth <= 0:
                            break
        return findings


class CErrorCodeNotPropagatedDetector:
    """F层: ret=foo(...) 后 if(ret) 分支未向上返回错误码"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            m = re.search(r'\((ret|rc|status|err|result)\s*\)\s*=\s*\w+\s*\([^)]*\)', line)
            if not m:
                m = re.search(r'\b(ret|rc|status|err|result)\s*=\s*\w+\s*\([^)]*\)', line)
            if not m:
                continue
            var = m.group(1)
            for j in range(i + 1, min(i + 8, len(lines))):
                if re.search(rf'if\s*\(\s*!?\s*{var}\b', lines[j]):
                    block_tail = ''.join(lines[j:j + 8])
                    if not re.search(r'\b(?:return|goto|throw|abort)\b', block_tail):
                        findings.append({
                            'event_id': f'C_ERR_CODE_DROP_{i+1}', 'line': i + 1, 'severity': 'P1',
                            'category': 'F_ERROR',
                            'description': f'错误路径未向上传递错误码(无return/goto/throw): {lines[j].strip()[:60]}',
                            'causal_chain': f'P[ret] -> E[check but no propagate] -> F[上层无感知]',
                            'suggestion': '错误分支 return 错误码 / goto error标签',
                        })
                    break
        return findings


class CCloseReturnIgnoredDetector:
    """F层: fclose()/free() 返回值/结果被忽略（关闭/释放失败未感知）"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if re.match(r'^\s*(?:fclose|fcloseall)\s*\([^)]*\)\s*;', stripped) and '=' not in stripped:
                findings.append({
                    'event_id': f'C_CLOSE_IGNORE_{i+1}', 'line': i + 1, 'severity': 'P2',
                    'category': 'F_ERROR',
                    'description': f'fclose() 返回值被忽略: {stripped[:80]}',
                    'causal_chain': f'P[fclose] -> E[ignore] -> F[写盘失败/数据截断不可见]',
                    'suggestion': '检查 fclose() != 0（写尾失败）',
                })
        return findings


class CErrorPathNoReturnDetector:
    """F层: 错误分支进入后无出口(return/goto/abort)，可能落入错误状态继续执行"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'if\s*\([^)]*\b(error|err)\b[^)]*\)\s*\{', line):
                block = ''.join(lines[i:i + 10])
                if not re.search(r'\b(?:return|goto|abort|exit|break|continue)\b', block):
                    findings.append({
                        'event_id': f'C_ERR_NO_RETURN_{i + 1}', 'line': i + 1, 'severity': 'P1',
                        'category': 'F_ERROR',
                        'description': f'错误分支无出口(return/goto/abort): {line.strip()[:60]}',
                        'causal_chain': f'P[error] -> E[no exit] -> F[错误状态继续执行]',
                        'suggestion': '错误分支必须 return/goto 终止或显式恢复',
                    })
        return findings


class CPanicAbortDetector:
    """F层: panic()/abort() 裸调用，无错误文案/日志上下文"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if re.search(r'\b(?:panic|abort)\s*\(', stripped) and not re.search(r'(?:panic|abort)f?\s*\(\s*["\']\w+', stripped):
                findings.append({
                    'event_id': f'C_PANIC_ABORT_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'F_ERROR',
                    'description': f'panic/abort 裸调用，无上下文: {stripped[:80]}',
                    'causal_chain': f'P[unexpected] -> E[panic/abort] -> F[进程崩溃无诊断]',
                    'suggestion': '终止前先记录错误原因/日志',
                })
        return findings


# ---------- E层 控制流 (category=E_CONTROL) ----------

class CCaseFallThroughDetector:
    """E层: switch case 尾无 break/return 导致穿透"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if re.match(r'\s*case\s+\w+\s*:', line.strip()):
                body = []
                for j in range(i + 1, len(lines)):
                    if re.match(r'\s*(?:case\s+\w+\s*:|default\s*:|})', lines[j]):
                        break
                    body.append(lines[j])
                if body and not re.search(r'\b(?:break|return|goto|throw|continue)\b', '\n'.join(body)):
                    findings.append({
                        'event_id': f'C_CASE_FALLTHROUGH_{i + 1}', 'line': i + 1, 'severity': 'P1',
                        'category': 'E_CONTROL',
                        'description': f'switch case 缺 break/return，存在穿透: {line.strip()[:60]}',
                        'causal_chain': f'P[case] -> E[no break] -> F[穿透执行]',
                        'suggestion': 'case 尾部加 break/return，或显式标注 [[fallthrough]]',
                    })
        return findings


class CInfiniteWhileDetector:
    """E层: while(1)/while(true) 前向无 break 退出口"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'while\s*\(\s*(?:1|true|TRUE)\s*\)\s*\{', line):
                window = '\n'.join(lines[i + 1:i + 16])
                if 'break' not in window:
                    findings.append({
                        'event_id': f'C_WHILE_1_{i + 1}', 'line': i + 1, 'severity': 'P2',
                        'category': 'E_CONTROL',
                        'description': f'while(1) 循环 15 行内未见 break: {line.strip()[:60]}',
                        'causal_chain': f'P[loop] -> E[no exit] -> F[死循环/阻塞]',
                        'suggestion': '为退出设置 break/bool 标志，避免恒循环',
                    })
        return findings


class CUnboundedLoopDetector:
    """E层: 循环体内 continue 且无进展语句(自增/自减)"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'(?:while|for)\s*\([^)]*\)\s*\{', line):
                window = '\n'.join(lines[i:i + 25])
                if re.search(r'\bcontinue\s*;', window) and not re.search(r'\+\+|--|\+=|-=', window):
                    findings.append({
                        'event_id': f'C_CONTINUE_INF_{i + 1}', 'line': i + 1, 'severity': 'P1',
                        'category': 'E_CONTROL',
                        'description': f'循环含 continue 但无进展语句，可能不收敛: {line.strip()[:60]}',
                        'causal_chain': f'P[loop] -> E[continue no progress] -> F[不终止]',
                        'suggestion': '确保 continue 前推进循环变量',
                    })
        return findings


class CUnboundedRecursionDetector:
    """E层: 递归函数体内无终止基例(if(...) return)"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            m = re.search(r'\b(\w+)\s*\([^)]*\)\s*\{', line)
            if not m:
                continue
            fname = m.group(1)
            if fname in ('if', 'for', 'while', 'switch'):
                continue
            body = ''.join(lines[i:i + 60])
            if re.search(rf'\b{fname}\s*\(', body[i + len(line):]) and not re.search(r'if\s*\([^)]*\)\s*\{[^}]*\breturn\b', body):
                findings.append({
                    'event_id': f'C_RECURSION_NO_BASE_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'E_CONTROL',
                    'description': f'递归函数 {fname} 未见终止基例(if+return): {line.strip()[:60]}',
                    'causal_chain': f'P[self call] -> E[no base case] -> F[栈溢出]',
                    'suggestion': '为递归增加基例判断 (if (base) return ...)',
                })
        return findings


class CGoToAbuseDetector:
    """E层: goto 滥用(文件中 goto 出现 >2 次)"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        gotos = [i for i, l in enumerate(lines) if re.search(r'\bgoto\s+\w+\s*;', l)]
        if len(gotos) > 2:
            findings.append({
                'event_id': f'C_GOTO_ABUSE_{gotos[0] + 1}', 'line': gotos[0] + 1, 'severity': 'P2',
                'category': 'E_CONTROL',
                'description': f'goto 使用过多({len(gotos)} 处)，破坏结构化控制流',
                'causal_chain': f'P[goto] -> E[spaghetti] -> F[难维护/难验证]',
                'suggestion': '用函数/错误标签替代过多 goto',
            })
        return findings


class CEmptyBranchDetector:
    """E层: 空 if/else 分支"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if re.search(r'(?:if|else)\s*\([^)]*\)?\s*\{\s*\}', stripped) or re.search(r'else\s*\{\s*\}', stripped):
                findings.append({
                    'event_id': f'C_EMPTY_BRANCH_{i + 1}', 'line': i + 1, 'severity': 'P2',
                    'category': 'E_CONTROL',
                    'description': f'空分支(if/else),逻辑缺失: {stripped[:80]}',
                    'causal_chain': f'P[?] -> E[empty branch] -> F[该路径无行为]',
                    'suggestion': '补全分支逻辑或移除空块',
                })
        return findings


# ---------- E层 资源 (category=E_RESOURCE) ----------

class CAllocPathLeakDetector:
    """E层: malloc 后错误分支 return 时未 free(错误路径泄漏)"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            m = re.search(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(', line)
            if not m:
                continue
            var = m.group(1)
            for j in range(i + 1, min(i + 12, len(lines))):
                if re.search(r'if\s*\([^)]*\)', lines[j]) and re.search(r'\breturn\b', ''.join(lines[j:j + 3])):
                    if not re.search(rf'\bfree\s*\(\s*{var}\s*\)', ''.join(lines[i + 1:j + 4])):
                        findings.append({
                            'event_id': f'C_ALLOC_PATH_LEAK_{i + 1}', 'line': i + 1, 'severity': 'P1',
                            'category': 'E_RESOURCE',
                            'description': f'malloc 错误路径 return 未释放 {var}: {lines[j].strip()[:60]}',
                            'causal_chain': f'P[malloc] -> E[err return no free] -> F[内存泄漏]',
                            'suggestion': '错误分支先 free(var) 再 return',
                        })
                    break
        return findings


class CMutexErrorUnlockDetector:
    """E层(P0): 函数内锁定后错误路径 return 前未解锁"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if not re.search(r'pthread_mutex_lock\s*\(', line):
                continue
            for j in range(i + 1, min(i + 40, len(lines))):
                if re.search(r'\b(?:return|goto)\b', lines[j]) and not re.search(r'pthread_mutex_unlock\s*\(', ''.join(lines[i + 1:j])):
                    findings.append({
                        'event_id': f'C_MUTEX_UNLOCK_{i + 1}', 'line': i + 1, 'severity': 'P0',
                        'category': 'E_RESOURCE',
                        'description': f'锁定后错误/正常路径 return 前未解锁: {lines[j].strip()[:60]}',
                        'causal_chain': f'P[lock] -> E[return no unlock] -> F[死锁/锁泄漏]',
                        'suggestion': 'return 前先 pthread_mutex_unlock 或 RAII 守卫',
                    })
                    break
        return findings


class CDbConnectionLeakDetector:
    """E层: 数据库连接打开后前40行未见关闭"""
    DB_OPEN = r'(?:sqlite3_open|mysql_init|mysql_real_connect|PQconnectdb|db_connect|sqlite3_open_v2)\s*\('
    DB_CLOSE = r'(?:sqlite3_close|mysql_close|PQfinish|db_close|deinit)'

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            m = re.search(r'(\w+)\s*=\s*[^;]*' + self.DB_OPEN, line)
            if not m:
                continue
            var = m.group(1)
            window = '\n'.join(lines[i + 1:i + 41])
            if not re.search(self.DB_CLOSE + r'|' + rf'{re.escape(var)}\.close\s*\)', window):
                findings.append({
                    'event_id': f'C_DB_LEAK_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'E_RESOURCE',
                    'description': f'数据库连接打开后 40 行内未见关闭: {line.strip()[:60]}',
                    'causal_chain': f'P[db_open] -> E[no close] -> F[连接泄漏]',
                    'suggestion': '确保所有路径关闭数据库连接',
                })
        return findings


# ---------- MOD层 契约 (category=MOD_CONTRACT) ----------

class CHardcodedWhitelistDetector:
    """MOD层: 硬编码白名单/黑名单数据(数组字面量)"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if re.search(r'(?:allowed|whitelist|blocklist|denylist|grace)\w*\s*(?:\[[^]]*\]\s*)?=\s*\{', stripped, re.IGNORECASE):
                findings.append({
                    'event_id': f'C_HARDCODE_WHL_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'MOD_CONTRACT',
                    'description': f'硬编码名单(白/黑名单)字面量: {stripped[:80]}',
                    'causal_chain': f'P[literal list] -> E[hard coded] -> F[不可配置/难维护]',
                    'suggestion': '名单移入配置文件/常量表，避免硬编码',
                })
        return findings


class CInputNotSanitizedDetector:
    """MOD层: 危险字符串函数直接拼接外部输入且前向无净化"""
    DANGER = rb'strcpy|strcat|sprintf'
    USER = rb'argv|input|user|data|req|param|query|buf|cmd'

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if re.search(r'(?:strcpy|strcat|sprintf)\s*\([^,]*,\s*\w', line):
                # 前向是否有净化/长度校验
                before = '\n'.join(lines[max(0, i - 6):i])
                if not re.search(r'(?:sanitize|strip|strn|snprint|bound|check|validate|sscanf)', before, re.IGNORECASE):
                    findings.append({
                        'event_id': f'C_INPUT_UNSANITIZED_{i + 1}', 'line': i + 1, 'severity': 'P1',
                        'category': 'MOD_CONTRACT',
                        'description': f'字符串拼接外部输入且未见净化/长度校验: {line.strip()[:70]}',
                        'causal_chain': f'P[input] -> E[unsafe concat] -> F[溢出/注入]',
                        'suggestion': '使用 strncpy/snprintf 并做输入清洗',
                    })
        return findings


class CMagicNumberDetector:
    """MOD层: 裸魔法数字(≥3位)用于比较/赋值"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if re.search(r'if\s*\([^)]*\b(?:==|>=|<=|>|<)\s*\d{3,}\b', stripped):
                mag = re.search(r'(?:==|>=|<=|>|<)\s*(\d{3,})', stripped)
                findings.append({
                    'event_id': f'C_MAGIC_NUM_{i + 1}', 'line': i + 1, 'severity': 'P2',
                    'category': 'MOD_CONTRACT',
                    'description': f'裸魔法数字 {mag.group(1) if mag else ""} 参与比较: {stripped[:70]}',
                    'causal_chain': f'P[magic] -> E[compare] -> F[语义不明/难改]',
                    'suggestion': '用具名常量替代魔法数字',
                })
        return findings


class CHardcodedEndpointDetector:
    """MOD层: 硬编码 IP/端口/URL 端点"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if re.search(r'\d{1,3}(?:\.\d{1,3}){3}\s*[:"]', stripped) or re.search(r'https?://[^\s"\' ]+', stripped):
                findings.append({
                    'event_id': f'C_HARDCODE_EP_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'MOD_CONTRACT',
                    'description': f'硬编码端点(IP/URL): {stripped[:80]}',
                    'causal_chain': f'P[literal endpoint] -> E[hard coded] -> F[不可配置/信息泄漏]',
                    'suggestion': '端点移入配置，避免硬编码 IP/URL',
                })
        return findings


class CWeakCryptoDetector:
    """MOD层: 弱加密算法/危险默认权限"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(source.split('\n')):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if re.search(r'\b(?:MD5|SHA1|DES|arc4|rc4|rand\s*\()', stripped, re.IGNORECASE) or re.search(r'chmod\s*\([^)]*\b(?:0?666|0?777|0777|0666)\b', stripped):
                findings.append({
                    'event_id': f'C_WEAK_CRYPTO_{i + 1}', 'line': i + 1, 'severity': 'P1',
                    'category': 'MOD_CONTRACT',
                    'description': f'疑似弱加密算法或危险默认权限: {stripped[:80]}',
                    'causal_chain': f'P[weak crypto] -> E[use] -> F[安全弱点]',
                    'suggestion': '使用 SHA-256/AES/西利随机源，收紧文件权限',
                })
        return findings


# ============================================================
# 统一入口
# ============================================================

ALL_OPERATORS = [
    PlaceholderDetector(),
    LogicChainVerifier(),
    DeadCodeDetector(),
    MathPropertyVerifier(),
    StringLiteralValidator(),
    UnimplementedDeclDetector(),
    BufferOverflowDetector(),
    UninitMemoryDetector(),
    ResourceLeakDetector(),
    IntegerOverflowDetector(),
    PathCoverageAnalyzer(),
    RaceConditionDetector(),
    DangerousFunctionDetector(),
    MallocNullCheckDetector(),
    # ---- P1 L6 (Task6): F/E/MOD 层新增 ----
    CReturnValueIgnoredDetector(),
    CSensitiveInfoLogDetector(),
    CSilentErrorBranchDetector(),
    CUnprotectedContinueDetector(),
    CErrorCodeNotPropagatedDetector(),
    CCloseReturnIgnoredDetector(),
    CErrorPathNoReturnDetector(),
    CPanicAbortDetector(),
    CCaseFallThroughDetector(),
    CInfiniteWhileDetector(),
    CUnboundedLoopDetector(),
    CUnboundedRecursionDetector(),
    CGoToAbuseDetector(),
    CEmptyBranchDetector(),
    CAllocPathLeakDetector(),
    CMutexErrorUnlockDetector(),
    CDbConnectionLeakDetector(),
    CHardcodedWhitelistDetector(),
    CInputNotSanitizedDetector(),
    CMagicNumberDetector(),
    CHardcodedEndpointDetector(),
    CWeakCryptoDetector(),
]

def run_pef_operators(source_code: str) -> List[Dict]:
    """运行全部PEF算子并返回合并的发现列表（每条 finding 标记算子来源 source）"""
    all_findings = []
    for op in ALL_OPERATORS:
        try:
            findings = op.detect(source_code)
            for f in findings:
                f["source"] = op.__class__.__name__  # Task8: 独立证据源辨识
            all_findings.extend(findings)
        except (TypeError, ValueError, RuntimeError, OSError, KeyError, IndexError) as e:
            all_findings.append({
                'event_id': f'PEF_ERROR_{op.__class__.__name__}',
                'line': 0, 'severity': 'INFO',
                'category': 'OPERATOR_ERROR',
                'description': f'算子{op.__class__.__name__}执行异常: {e}',
                'suggestion': '检查算子实现'
            })
    return all_findings

__all__ = [
    'PlaceholderDetector', 'LogicChainVerifier', 'DeadCodeDetector',
    'MathPropertyVerifier', 'StringLiteralValidator', 'UnimplementedDeclDetector',
    'BufferOverflowDetector', 'UninitMemoryDetector', 'ResourceLeakDetector',
    'IntegerOverflowDetector', 'PathCoverageAnalyzer', 'RaceConditionDetector',
    'DangerousFunctionDetector', 'MallocNullCheckDetector',
    'CReturnValueIgnoredDetector', 'CSensitiveInfoLogDetector', 'CSilentErrorBranchDetector',
    'CUnprotectedContinueDetector', 'CErrorCodeNotPropagatedDetector', 'CCloseReturnIgnoredDetector',
    'CErrorPathNoReturnDetector', 'CPanicAbortDetector', 'CCaseFallThroughDetector',
    'CInfiniteWhileDetector', 'CUnboundedLoopDetector', 'CUnboundedRecursionDetector',
    'CGoToAbuseDetector', 'CEmptyBranchDetector', 'CAllocPathLeakDetector',
    'CMutexErrorUnlockDetector', 'CDbConnectionLeakDetector', 'CHardcodedWhitelistDetector',
    'CInputNotSanitizedDetector', 'CMagicNumberDetector', 'CHardcodedEndpointDetector',
    'CWeakCryptoDetector',
    'run_pef_operators', 'ALL_OPERATORS'
]
