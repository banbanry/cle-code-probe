# TRAE Work Order: Fix Silent Exception Swallowing + Hardcoded Paths

**Priority**: P1 (Production stability)
**Estimated Effort**: 2-3 hours
**Scope**: integration_v2 project

---

## Background

Full 10-layer code audit of integration_v2 found:
- 0 P0 (no crash-level issues) ✅
- 32 P1: Silent exception swallowing (`except: pass`) — errors completely hidden
- 3 P2: Weak MD5 hash in test files
- 6 P3: Hardcoded absolute paths (portability risk for EXE packaging)

This work order covers P1 + P2 + P3 fixes.

---

## Task 1: Fix Silent Exception Swallowing (P1, 32 locations)

### Problem
Currently `except Exception: pass` silently swallows all errors, making production debugging impossible.

### Files to fix (by priority):

#### 1.1 business_hongxin/exporters.py (11 locations)
- Lines: 75, 308, 316, 367, 399, 423, 455, 579, ...
- Change `except Exception: pass` to:
  ```python
  except Exception as e:
      logger.warning("Exporter error at line %d: %s: %s", sys._getframe().f_lineno, type(e).__name__, str(e)[:200])
  ```

#### 1.2 business_hongxin/converter_excel_interface.py (8 locations)
- Lines: 119, 126, 137, 143, 175, 243, 338, 417
- Same fix as above

#### 1.3 business_hongxin/hongxin_pipeline.py (5 locations)
- Same fix

#### 1.4 business_hongxin/utils.py (3 locations)
- Same fix

#### 1.5 Other files (5 locations total)
- invoice_template_engine.py: 2
- cache_operator.py: 1
- converter_parser.py: 1
- import_declaration_engine.py: 1

### Requirements
1. **DO NOT** remove the `except` block (batch fault tolerance is intentional)
2. **DO** add `logger.warning()` before `pass` to record the error
3. Include: exception type, error message (truncated to 200 chars), file/line
4. Use the existing `logger` instance (already imported in most files)
5. **DO NOT** change the behavior — just add logging

---

## Task 2: Fix Weak MD5 Hash Warnings (P2, 3 locations)

### Problem
Bandit flagged B324: weak MD5 hash usage.

### Files:
1. `tests/test_hexiao_engine.py:65`
2. `tests/test_import_declaration_engine.py:132`
3. `tests/test_import_declaration_engine.py:133`

### Fix:
Change `hashlib.md5()` to `hashlib.md5(usedforsecurity=False)`

---

## Task 3: Fix Hardcoded Absolute Paths (P3, 6 locations)

### Problem
Hardcoded paths will break when packaged as EXE.

### Files:

#### 3.1 business_hongxin/invoice_template_engine.py (2 locations)
- Line 1637: `r'D:\810\SI\CRO202608312439-CATHAY.xlsx'`
- Line 1638: `r'D:\810\发票\CRO202608312439-CATHAY.xlsx'`

**Fix**: These look like test/debug paths. If they're just examples in comments or demo code, add a comment marking them as sample paths. If they're actually used, change to relative path or config variable.

#### 3.2 ocr_plugin/config.py (4 locations)
- Line 18: `r'C:\Program Files\Tesseract-OCR\tesseract.exe'`
- Line 19: `r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe'`
- Line 25: return hardcoded path
- Line 34: hardcoded tessdata path

**Fix**: Use `shutil.which('tesseract')` first, fall back to these paths.

---

## Out of Scope

1. **161 wide `except Exception`** — this is intentional batch fault tolerance design, DO NOT touch
2. LLM semantic review findings — handled separately
3. PEF structured review — handled separately

---

## Verification

After fixes:
1. Re-run bandit: `bandit -r integration_v2/`
2. Re-run CLE probe: `cle_deploy.py audit integration_v2/`
3. Confirm: silent except count drops from 32 → 0
4. Confirm: MD5 B324 warnings disappear
5. Confirm: hardcoded path warnings disappear

---

## Acceptance Criteria

- [ ] All 32 silent except blocks have `logger.warning()` added
- [ ] All 3 MD5 calls have `usedforsecurity=False`
- [ ] All 6 hardcoded paths are fixed or marked as sample
- [ ] Existing batch fault tolerance behavior unchanged
- [ ] No new syntax errors introduced
