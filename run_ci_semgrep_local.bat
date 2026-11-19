@echo off
chcp 65001 >nul
cd /d "%~dp0"
set TAG=aiws-semgrep:4.7.0-semgrep1.181.0
set OUT=%~dp0security-config\semgrep\reports\ci_local_v470_2026-10-26
if not exist "%OUT%" mkdir "%OUT%"
set LOG=%OUT%\run_log.txt
echo Chay thu anh Docker Semgrep: build anh roi quet repo AI-WhiteSec-Ci trong container. Lan dau khoang 3-8 phut.
echo ===== bat dau %DATE% %TIME% ===== > "%LOG%"
echo ===== docker version ===== >> "%LOG%"
docker version --format "client {{.Client.Version}} / server {{.Server.Version}}" >> "%LOG%" 2>&1
if errorlevel 1 (echo KHONG CO DOCKER hoac Docker Desktop chua chay >> "%LOG%" & goto end)
set DOCKER_BUILDKIT=1
echo ===== docker build ===== >> "%LOG%"
docker build --progress=plain -f security-config\semgrep\ci\Dockerfile -t %TAG% . >> "%LOG%" 2>&1
echo build exit: %ERRORLEVEL% >> "%LOG%"
if errorlevel 1 goto end
echo ===== docker run: quet AI-WhiteSec-Ci ===== >> "%LOG%"
docker run --rm -v "%~dp0..\AI-WhiteSec-Ci:/src:ro" -v "%OUT%:/out" %TAG% --repo /src --repo-name AI-WhiteSec-Ci --out /out/semgrep-results.json --scope-out /out/scope.json >> "%LOG%" 2>&1
echo scan exit: %ERRORLEVEL% >> "%LOG%"
echo ===== kich thuoc anh ===== >> "%LOG%"
docker image ls %TAG% >> "%LOG%" 2>&1
:end
echo ===== XONG %DATE% %TIME% ===== >> "%LOG%"
type "%LOG%"
pause
