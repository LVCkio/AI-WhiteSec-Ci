@echo off
chcp 65001 >nul
cd /d "%~dp0..\.."
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=python
if not exist "security-config\semgrep\reports" mkdir "security-config\semgrep\reports"
echo Dang kiem tra bo rule Semgrep... (khoang 1-3 phut)
"%PY%" security-config\semgrep\tools\ruleset.py all > "security-config\semgrep\reports\run_log.txt" 2>&1
echo Exit code: %ERRORLEVEL% >> "security-config\semgrep\reports\run_log.txt"
type "security-config\semgrep\reports\run_log.txt"
echo.
echo Xong. Ket qua: security-config\semgrep\reports\rule_test_report.md
pause
