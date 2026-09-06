#!/usr/bin/env python3
# ============================================================
# PEF CLE Code Probe — Python AST Context Analyzer
# Source: https://github.com/banbanry/cle-code-probe
# Author: banbanry (沈鹭)
# License: MIT
# π-Anchor: SecurePiDigitProvider — source_hash + step → SHA-256 → π digit
# ============================================================
"""
Python AST 上下文分析框架 — 解决正则匹配导致的误报问题。

核心能力：
1. Try/Except 块识别 — 精确判断代码行是否在 try 块内，以及对应的 except 块内容
2. Except 块质量分析 — 判断 except 块内是否有日志记录/重新抛出/错误返回值/UI兜底
3. 文件来源可信度判断 — 判断 load_workbook/open 的文件参数是否来自用户输入
4. 测试代码识别 — 根据文件名/函数名/类名判断是否是测试代码
5. 函数上下文识别 — 获取代码行所在的函数/类信息

设计原则：
- 基于 Python 标准库 ast 模块，无需额外依赖
- 容错设计：AST 解析失败时回退到正则匹配（不影响原有功能）
- 与现有算子无缝集成：提供辅助函数，算子可选择性使用
"""

import ast
import re
from typing import List, Dict, Optional, Tuple, Set


# ============================================================
# AST 解析器（容错设计）
# ============================================================

class PythonASTParser:
    """Python AST 解析器，容错设计：解析失败时返回 None"""

    def __init__(self, source: str):
        self.source = source
        self.lines = source.split('\n')
        self.tree = None
        self.parse_error = None
        try:
            self.tree = ast.parse(source)
        except SyntaxError as e:
            self.parse_error = e

    @property
    def is_valid(self) -> bool:
        return self.tree is not None


# ============================================================
# Try/Except 块识别
# ============================================================

class TryExceptAnalyzer:
    """Try/Except 块分析器 — 精确识别 try 块范围和对应的 except 块内容"""

    def __init__(self, parser: PythonASTParser):
        self.parser = parser
        self.try_blocks: List[Dict] = []  # [{try_start, try_end, except_handlers: [{start, end, types, body_nodes}]}]
        self._analyze()

    def _analyze(self):
        """遍历AST，收集所有try/except块"""
        if not self.parser.is_valid:
            return

        class TryVisitor(ast.NodeVisitor):
            def __init__(self, lines):
                self.lines = lines
                self.try_blocks = []

            def visit_Try(self, node):
                # try块范围
                try_start = node.lineno
                try_end = node.end_lineno if hasattr(node, 'end_lineno') else try_start

                # 收集except handlers
                handlers = []
                for handler in node.handlers:
                    handler_start = handler.lineno
                    handler_end = handler.end_lineno if hasattr(handler, 'end_lineno') else handler_start
                    # 捕获的异常类型
                    exc_types = []
                    if handler.type:
                        if isinstance(handler.type, ast.Tuple):
                            for elt in handler.type.elts:
                                if isinstance(elt, ast.Name):
                                    exc_types.append(elt.id)
                                elif isinstance(elt, ast.Attribute):
                                    exc_types.append(elt.attr)
                        elif isinstance(handler.type, ast.Name):
                            exc_types.append(handler.type.id)
                        elif isinstance(handler.type, ast.Attribute):
                            exc_types.append(handler.type.attr)

                    handlers.append({
                        'start': handler_start,
                        'end': handler_end,
                        'types': exc_types,
                        'body_nodes': handler.body,
                        'name': handler.name,  # as e 中的 e
                    })

                self.try_blocks.append({
                    'try_start': try_start,
                    'try_end': try_end,
                    'handlers': handlers,
                })
                self.generic_visit(node)

        visitor = TryVisitor(self.parser.lines)
        visitor.visit(self.parser.tree)
        self.try_blocks = visitor.try_blocks

    def is_in_try_block(self, line_num: int) -> bool:
        """判断指定行是否在 try 块内（包括 try 主体和 except 块）"""
        for block in self.try_blocks:
            if block['try_start'] <= line_num <= block['try_end']:
                return True
        return False

    def get_except_handlers_for_line(self, line_num: int) -> List[Dict]:
        """获取包含指定行的 try 块对应的所有 except handlers"""
        for block in self.try_blocks:
            if block['try_start'] <= line_num <= block['try_end']:
                return block['handlers']
        return []

    def has_badzip_catch(self, line_num: int) -> bool:
        """判断指定行所在的 try 块是否有 BadZipFile/宽泛异常捕获"""
        handlers = self.get_except_handlers_for_line(line_num)
        for handler in handlers:
            # 检查是否捕获 BadZipFile/InvalidFileException
            for exc_type in handler['types']:
                if 'BadZipFile' in exc_type or 'InvalidFile' in exc_type or 'zipfile' in exc_type.lower():
                    return True
            # 裸 except 或 except Exception 也能捕获 BadZipFile
            if not handler['types'] or 'Exception' in handler['types'] or 'BaseException' in handler['types']:
                return True
        return False


# ============================================================
# Except 块质量分析
# ============================================================

class ExceptBlockQualityAnalyzer:
    """Except 块质量分析器 - 判断 except 块是合理防御还是静默吞错"""

    # 日志记录模式
    LOG_PATTERNS = [
        r'logger\.(error|warning|warn|exception|critical|info|debug)',
        r'logging\.(error|warning|warn|exception|critical)',
        r'log\.(error|warning|warn|exception)',
        r'print\s*\(',  # print 也算简单的日志记录
        r'traceback\.(print_exc|format_exc)',
        r'sys\.stderr\.write',
    ]

    # 重新抛出模式
    RAISE_PATTERNS = [
        r'^\s*raise\s*$',  # 裸 raise
        r'^\s*raise\s+\w+',  # raise 新异常
        r'^\s*raise\s+\w+\s*\(',
    ]

    # 错误返回值模式
    ERROR_RETURN_PATTERNS = [
        r'return\s+None',
        r'return\s+False',
        r'return\s+\{\}',
        r'return\s+\[\]',
        r'return\s+""',
        r"return\s+''",
        r'return\s+error',
        r'return\s+.*error',
        r'return\s+.*Error',
        r'return\s+.*reject',
        r'return\s+.*fail',
        r'return\s+.*FAIL',
    ]

    # UI 兜底模式（合理的用户提示）
    UI_FALLBACK_PATTERNS = [
        r'messagebox\.(showerror|showwarning|showinfo)',
        r'QMessageBox\.(critical|warning|information)',
        r'wx\.MessageBox',
        r'gtk\.MessageDialog',
        r'self\.statusBar\(\)\.showMessage',
        r'statusbar\.showMessage',
        r'QStatusBar',
        r'toast',
        r'notification',
        r'alert\s*\(',
    ]

    def __init__(self, parser: PythonASTParser):
        self.parser = parser

    def analyze_except_block(self, handler: Dict) -> Dict:
        """分析单个 except handler 的质量

        返回：
        {
            'has_logging': bool,        # 是否有日志记录
            'has_raise': bool,           # 是否重新抛出
            'has_error_return': bool,    # 是否有错误返回值
            'has_ui_fallback': bool,     # 是否有UI兜底
            'is_silent': bool,           # 是否是静默吞错（只有pass/continue）
            'quality_score': int,        # 质量评分 0-100（越高越合理）
            'reason': str,               # 分析原因
        }
        """
        if not self.parser.is_valid:
            return self._fallback_analysis(handler)

        # 获取 except 块的源代码行
        start = handler['start']
        end = handler['end']
        block_lines = self.parser.lines[start-1:end]
        block_text = '\n'.join(block_lines)

        # 剥离 except 声明行，只看块内容
        body_lines = []
        in_body = False
        for line in block_lines:
            stripped = line.strip()
            if not in_body:
                if stripped.startswith('except'):
                    in_body = True
                    continue
            else:
                body_lines.append(line)
        body_text = '\n'.join(body_lines)

        # 分析各项
        has_logging = any(re.search(p, body_text) for p in self.LOG_PATTERNS)
        has_raise = any(re.search(p, body_text, re.MULTILINE) for p in self.RAISE_PATTERNS)
        has_error_return = any(re.search(p, body_text) for p in self.ERROR_RETURN_PATTERNS)
        has_ui_fallback = any(re.search(p, body_text) for p in self.UI_FALLBACK_PATTERNS)

        # 判断是否是静默吞错（只有 pass/continue/注释/空行）
        meaningful_lines = []
        for line in body_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped in ('pass', 'continue', '...'):
                continue
            meaningful_lines.append(stripped)
        is_silent = len(meaningful_lines) == 0

        # 质量评分
        score = 0
        reasons = []
        if has_logging:
            score += 30
            reasons.append('有日志记录')
        if has_raise:
            score += 30
            reasons.append('有重新抛出')
        if has_error_return:
            score += 20
            reasons.append('有错误返回值')
        if has_ui_fallback:
            score += 15
            reasons.append('有UI兜底提示')
        if is_silent:
            score = 0
            reasons.append('静默吞错（仅pass/continue）')

        # 捕获异常类型也影响评分
        exc_types = handler.get('types', [])
        if not exc_types:
            score = max(0, score - 10)  # 裸except扣分
            reasons.append('裸except（过宽）')
        elif 'Exception' in exc_types or 'BaseException' in exc_types:
            score = max(0, score - 5)  # except Exception扣分
            reasons.append('except Exception（过宽）')

        score = min(100, score)

        return {
            'has_logging': has_logging,
            'has_raise': has_raise,
            'has_error_return': has_error_return,
            'has_ui_fallback': has_ui_fallback,
            'is_silent': is_silent,
            'quality_score': score,
            'reason': '; '.join(reasons) if reasons else '未检测到明确的异常处理行为',
            'exc_types': exc_types,
        }

    def _fallback_analysis(self, handler: Dict) -> Dict:
        """AST解析失败时的回退分析（基于行号范围的简单正则）"""
        start = handler['start']
        end = handler['end']
        block_lines = self.parser.lines[start-1:end]
        block_text = '\n'.join(block_lines)

        has_logging = any(re.search(p, block_text) for p in self.LOG_PATTERNS)
        has_raise = any(re.search(p, block_text, re.MULTILINE) for p in self.RAISE_PATTERNS)
        is_silent = bool(re.search(r'except\s*[^:]*:\s*(?:pass|continue)\s*$', block_text, re.MULTILINE))

        score = 0
        if has_logging:
            score += 30
        if has_raise:
            score += 30
        if is_silent:
            score = 0

        return {
            'has_logging': has_logging,
            'has_raise': has_raise,
            'has_error_return': False,
            'has_ui_fallback': False,
            'is_silent': is_silent,
            'quality_score': score,
            'reason': '回退分析（AST解析失败）',
            'exc_types': handler.get('types', []),
        }


# ============================================================
# 文件来源可信度判断
# ============================================================

class FileSourceTrustAnalyzer:
    """文件来源可信度分析器 — 判断 load_workbook/open 的文件参数是否来自用户输入"""

    # 不可信来源的变量名/函数名模式
    UNTRUSTED_PATTERNS = [
        r'upload', r'user_input', r'user_file', r'request', r'form',
        r'input_file', r'input_path', r'external', r'untrusted',
        r'received', r'client', r'post_data', r'get_argument',
        r'request\.files', r'request\.form', r'sys\.argv',
    ]

    # 可信来源的变量名模式（程序自身生成的输出）
    TRUSTED_PATTERNS = [
        r'output', r'result', r'generated', r'temp', r'tmp',
        r'export', r'backup', r'archive', r'log', r'cache',
        r'config', r'settings', r'template', r'sample',
        r'test', r'fixture', r'mock',
    ]

    def __init__(self, parser: PythonASTParser):
        self.parser = parser

    def is_file_source_trusted(self, line_num: int, line_text: str) -> Tuple[bool, str]:
        """判断指定行的文件操作来源是否可信

        返回：(is_trusted, reason)
        - is_trusted=True: 程序自身生成的输出，可信，不应报P0
        - is_trusted=False: 用户上传/外部输入，不可信，应报P0
        """
        # 提取 load_workbook/open 的参数
        # 简单匹配：load_workbook(xxx) 或 open(xxx)
        arg_match = re.search(r'(?:load_workbook|open|ZipFile|read_excel)\s*\(([^,)]+)', line_text)
        if not arg_match:
            return False, '无法提取文件参数'

        arg = arg_match.group(1).strip()

        # 字符串常量（硬编码路径）— 通常是可信的配置/模板
        if (arg.startswith("'") and arg.endswith("'")) or \
           (arg.startswith('"') and arg.endswith('"')):
            return True, '硬编码字符串常量（配置/模板文件）'

        # 变量名分析
        var_name = arg.split('.')[0]  # 取 xxx.path 中的 xxx

        # 检查是否是不可信来源
        for pattern in self.UNTRUSTED_PATTERNS:
            if re.search(pattern, var_name, re.IGNORECASE):
                return False, f'变量名包含不可信来源标识: {pattern}'

        # 检查是否是可信来源
        for pattern in self.TRUSTED_PATTERNS:
            if re.search(pattern, var_name, re.IGNORECASE):
                return True, f'变量名包含可信来源标识: {pattern}'

        # 默认：无法判断，视为不可信（保守策略）
        return False, '无法判断来源，保守视为不可信'


# ============================================================
# 测试代码识别
# ============================================================

class TestCodeDetector:
    """测试代码识别器 — 判断文件/函数/类是否是测试代码"""

    # 测试文件名模式
    TEST_FILENAME_PATTERNS = [
        r'^test_', r'_test\.py$', r'/tests?/', r'/test/',
        r'conftest\.py$', r'__tests__',
    ]

    # 测试函数名模式
    TEST_FUNCTION_PATTERNS = [
        r'^test_', r'^test', r'_test$',
    ]

    # 测试类名模式
    TEST_CLASS_PATTERNS = [
        r'^Test', r'Test$', r'TestCase$', r'Tests$',
    ]

    # 测试框架导入
    TEST_FRAMEWORK_IMPORTS = [
        r'import\s+pytest', r'from\s+pytest',
        r'import\s+unittest', r'from\s+unittest',
        r'import\s+nose', r'from\s+nose',
    ]

    def __init__(self, parser: PythonASTParser, filename: str = ''):
        self.parser = parser
        self.filename = filename
        self._is_test_file = self._detect_test_file()

    def _detect_test_file(self) -> bool:
        """判断文件是否是测试文件"""
        # 文件名检查
        for pattern in self.TEST_FILENAME_PATTERNS:
            if re.search(pattern, self.filename, re.IGNORECASE):
                return True

        # 测试框架导入检查
        if self.parser.is_valid:
            source = self.parser.source
            for pattern in self.TEST_FRAMEWORK_IMPORTS:
                if re.search(pattern, source):
                    return True

        return False

    @property
    def is_test_file(self) -> bool:
        return self._is_test_file

    def is_test_function(self, line_num: int) -> bool:
        """判断指定行所在的函数是否是测试函数"""
        if not self.parser.is_valid:
            return False

        class FunctionFinder(ast.NodeVisitor):
            def __init__(self, target_line):
                self.target_line = target_line
                self.found_function = None

            def visit_FunctionDef(self, node):
                if node.lineno <= self.target_line <= (node.end_lineno or node.lineno):
                    self.found_function = node.name
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node):
                if node.lineno <= self.target_line <= (node.end_lineno or node.lineno):
                    self.found_function = node.name
                self.generic_visit(node)

        finder = FunctionFinder(line_num)
        finder.visit(self.parser.tree)

        if finder.found_function:
            for pattern in self.TEST_FUNCTION_PATTERNS:
                if re.search(pattern, finder.found_function):
                    return True

        return False

    def is_test_class(self, line_num: int) -> bool:
        """判断指定行所在的类是否是测试类"""
        if not self.parser.is_valid:
            return False

        class ClassFinder(ast.NodeVisitor):
            def __init__(self, target_line):
                self.target_line = target_line
                self.found_class = None

            def visit_ClassDef(self, node):
                if node.lineno <= self.target_line <= (node.end_lineno or node.lineno):
                    self.found_class = node.name
                self.generic_visit(node)

        finder = ClassFinder(line_num)
        finder.visit(self.parser.tree)

        if finder.found_class:
            for pattern in self.TEST_CLASS_PATTERNS:
                if re.search(pattern, finder.found_class):
                    return True

        return False

    def is_test_context(self, line_num: int) -> bool:
        """判断指定行是否在测试上下文中（测试文件/测试函数/测试类）"""
        if self.is_test_file:
            return True
        if self.is_test_function(line_num):
            return True
        if self.is_test_class(line_num):
            return True
        return False


# ============================================================
# 统一上下文分析器（整合所有分析能力）
# ============================================================

class PythonContextAnalyzer:
    """Python 上下文分析器 — 整合 AST 解析、Try/Except 分析、Except 质量分析、文件来源分析、测试代码识别"""

    def __init__(self, source: str, filename: str = ''):
        self.parser = PythonASTParser(source)
        self.try_except = TryExceptAnalyzer(self.parser)
        self.except_quality = ExceptBlockQualityAnalyzer(self.parser)
        self.file_source = FileSourceTrustAnalyzer(self.parser)
        self.test_detector = TestCodeDetector(self.parser, filename)

    @property
    def is_ast_valid(self) -> bool:
        return self.parser.is_valid

    def analyze_line(self, line_num: int, line_text: str = '') -> Dict:
        """分析指定行的完整上下文

        返回：
        {
            'in_try': bool,
            'has_badzip_catch': bool,
            'except_handlers': [...],
            'except_quality': {...},  # 第一个except handler的质量分析
            'is_test_context': bool,
            'file_source_trusted': bool,
            'file_source_reason': str,
        }
        """
        result = {
            'in_try': False,
            'has_badzip_catch': False,
            'except_handlers': [],
            'except_quality': None,
            'is_test_context': False,
            'file_source_trusted': False,
            'file_source_reason': '',
        }

        # Try/Except 分析
        result['in_try'] = self.try_except.is_in_try_block(line_num)
        if result['in_try']:
            handlers = self.try_except.get_except_handlers_for_line(line_num)
            result['except_handlers'] = handlers
            result['has_badzip_catch'] = self.try_except.has_badzip_catch(line_num)
            if handlers:
                result['except_quality'] = self.except_quality.analyze_except_block(handlers[0])

        # 测试代码识别
        result['is_test_context'] = self.test_detector.is_test_context(line_num)

        # 文件来源分析（仅对文件操作行）
        if line_text and re.search(r'(load_workbook|open\s*\(|ZipFile|read_excel)', line_text):
            trusted, reason = self.file_source.is_file_source_trusted(line_num, line_text)
            result['file_source_trusted'] = trusted
            result['file_source_reason'] = reason

        return result


# ============================================================
# 导出接口
# ============================================================

__all__ = [
    'PythonASTParser',
    'TryExceptAnalyzer',
    'ExceptBlockQualityAnalyzer',
    'FileSourceTrustAnalyzer',
    'TestCodeDetector',
    'PythonContextAnalyzer',
]
