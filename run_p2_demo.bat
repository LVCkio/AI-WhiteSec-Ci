@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set PATH=%~dp0.venv\Scripts;%PATH%
set OUT=security-config\semgrep\reports\p2_demo_2026-10-26
if not exist %OUT% mkdir %OUT%
set LOG=%OUT%\run_log.txt
echo P2: chay thu scan_repo.py tren repo AI-WhiteSec-Ci. Khoang 1-3 phut.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
"%PY%" security-config\semgrep\tools\scan_repo.py --repo ..\AI-WhiteSec-Ci --repo-name AI-WhiteSec-Ci --out %OUT%\semgrep-results.json --scope-out %OUT%\scope.json >> %LOG% 2>&1
echo scan exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
