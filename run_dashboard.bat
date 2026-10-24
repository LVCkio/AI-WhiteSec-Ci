@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=.venv\Scripts\python.exe
if not exist "%PY%" set PY=python
echo Dashboard AI-WhiteSec-CI: http://127.0.0.1:8765/  (Ctrl+C de dung)
"%PY%" dashboard\server.py %*
pause
