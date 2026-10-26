@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set PATH=%~dp0.venv\Scripts;%PATH%
set OUT=security-config\semgrep\reports\auth_rename_v470_2026-10-26
if not exist %OUT% mkdir %OUT%
set LOG=%OUT%\run_log.txt
echo v4.7.0: doi ten lop Auth. all + verify + unit test + do train/val v2.3. Khoang 3-5 phut.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py all >> %LOG% 2>&1
echo all exit: %ERRORLEVEL% >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py verify >> %LOG% 2>&1
echo verify exit: %ERRORLEVEL% >> %LOG%
"%PY%" -m unittest tests.test_class_alias tests.test_six_class_scope tests.test_dashboard >> %LOG% 2>&1
echo unittest exit: %ERRORLEVEL% >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split train --config security-config\semgrep\semgrep.yml --out %OUT% --baseline security-config\semgrep\reports\v23_v461_2026-10-26\train_samples.csv >> %LOG% 2>&1
echo train exit: %ERRORLEVEL% >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split val --config security-config\semgrep\semgrep.yml --out %OUT% --baseline security-config\semgrep\reports\v23_v461_2026-10-26\val_samples.csv >> %LOG% 2>&1
echo val exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
