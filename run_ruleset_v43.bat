@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set LOG=security-config\semgrep\reports\run_v43_log.txt
echo Ruleset v4.3.1: kiem tra metadata theo taxonomy, sinh bundle, chay 270 test, cap nhat manifest, verify, unit test. Khoang 3-10 phut.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
echo ===== semgrep --version (phai la 1.181.0) ===== >> %LOG%
.venv\Scripts\semgrep.exe --version >> %LOG% 2>&1
echo ===== ruleset.py all ===== >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py all >> %LOG% 2>&1
echo all exit: %ERRORLEVEL% >> %LOG%
echo ===== ruleset.py verify ===== >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py verify >> %LOG% 2>&1
echo verify exit: %ERRORLEVEL% >> %LOG%
echo ===== unit test: ten lop theo taxonomy + pham vi 6 lop + dashboard ===== >> %LOG%
"%PY%" -m unittest tests.test_class_alias tests.test_six_class_scope tests.test_dashboard >> %LOG% 2>&1
echo unittest exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
