@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set PATH=%~dp0.venv\Scripts;%PATH%
set OUT=security-config\semgrep\reports\regex_ast_v461_2026-10-26
set B=security-config\semgrep\reports\task12_v22_2026-10-26\v460
if not exist %OUT% mkdir %OUT%
set LOG=%OUT%\run_log.txt
echo v4.6.1: viet lai 5 rule regex tang high bang AST. all + verify + do train/val + quet thu repo. Khoang 5-10 phut.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
echo ===== ruleset.py all ===== >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py all >> %LOG% 2>&1
echo all exit: %ERRORLEVEL% >> %LOG%
echo ===== verify ===== >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py verify >> %LOG% 2>&1
echo verify exit: %ERRORLEVEL% >> %LOG%
echo ===== unit test ===== >> %LOG%
"%PY%" -m unittest tests.test_class_alias tests.test_six_class_scope >> %LOG% 2>&1
echo unittest exit: %ERRORLEVEL% >> %LOG%
echo ===== train v2.2 ===== >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split train --config security-config\semgrep\semgrep.yml --out %OUT% --baseline %B%\train_samples.csv >> %LOG% 2>&1
echo train exit: %ERRORLEVEL% >> %LOG%
echo ===== val v2.2 ===== >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split val --config security-config\semgrep\semgrep.yml --out %OUT% --baseline %B%\val_samples.csv >> %LOG% 2>&1
echo val exit: %ERRORLEVEL% >> %LOG%
echo ===== quet thu repo AI-WhiteSec-Ci ===== >> %LOG%
"%PY%" security-config\semgrep\tools\scan_repo.py --repo ..\AI-WhiteSec-Ci --repo-name AI-WhiteSec-Ci --out %OUT%\p2_demo_semgrep-results.json >> %LOG% 2>&1
echo scan exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
