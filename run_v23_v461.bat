@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set PATH=%~dp0.venv\Scripts;%PATH%
set OUT=security-config\semgrep\reports\v23_v461_2026-10-26
if not exist %OUT% mkdir %OUT%
set LOG=%OUT%\run_log.txt
echo Do Semgrep v4.6.1 tren train/val dataset v2.3 (khong dung test). Khoang 3-5 phut.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py verify >> %LOG% 2>&1
echo verify exit: %ERRORLEVEL% >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split train --config security-config\semgrep\semgrep.yml --out %OUT% >> %LOG% 2>&1
echo train exit: %ERRORLEVEL% >> %LOG%
"%PY%" security-config\semgrep\tools\evaluate_supplement_v22.py --split val --config security-config\semgrep\semgrep.yml --out %OUT% >> %LOG% 2>&1
echo val exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
