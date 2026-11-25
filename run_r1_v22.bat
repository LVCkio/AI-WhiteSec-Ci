@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
set PATH=%~dp0.venv\Scripts;%PATH%
set LOG=security-config\semgrep\reports\run_r1_v22_log.txt
echo R1: do nen Semgrep tren train/val v2.2 va kiem tra rule chinh tu mau trung. Khoang 10-20 phut, dung tat cua so.
echo ===== bat dau %DATE% %TIME% ===== > %LOG%
echo ===== verify ===== >> %LOG%
"%PY%" security-config\semgrep\tools\ruleset.py verify >> %LOG% 2>&1
echo verify exit: %ERRORLEVEL% >> %LOG%
echo ===== train v2.2 ===== >> %LOG%
"%PY%" 34_baseline_v22.py --split train >> %LOG% 2>&1
echo train exit: %ERRORLEVEL% >> %LOG%
echo ===== val v2.2 ===== >> %LOG%
"%PY%" 34_baseline_v22.py --split val >> %LOG% 2>&1
echo val exit: %ERRORLEVEL% >> %LOG%
echo ===== rule chinh tu mau trung (21_rule_metrics tren tuning_subset) ===== >> %LOG%
"%PY%" 21_rule_metrics.py --input security-config\semgrep\reports\r1_overlap_v22_2026-10-25_tuning_subset_uniq.csv --out r1_overlap_rules_v22 >> %LOG% 2>&1
echo overlap exit: %ERRORLEVEL% >> %LOG%
echo ===== XONG %DATE% %TIME% ===== >> %LOG%
type %LOG%
pause
