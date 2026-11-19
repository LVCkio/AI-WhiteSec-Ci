@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem 19/11/2026: tag anh lay tu ruleset-manifest.json (truoc day ghi tay, da lech voi ruleset that)
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "$m = Get-Content 'security-config\semgrep\ruleset-manifest.json' -Raw | ConvertFrom-Json; $m.ruleset_version + '-semgrep' + $m.semgrep_version_pinned"`) do set VER=%%v
if not defined VER (echo Khong doc duoc security-config\semgrep\ruleset-manifest.json & pause & exit /b 1)
set LOCAL=aiws-semgrep:%VER%
set REMOTE=registry.gitlab.com/fpt-edu-kltn-group/ai-whitesec-ci/aiws-semgrep:%VER%
set LOG=%~dp0security-config\semgrep\reports\ci_local_2026-10-26\push_registry_log.txt
echo Day image Semgrep len GitLab Container Registry.
echo Buoc 1: dang nhap registry.gitlab.com
echo   Username: ten dang nhap GitLab cua ban
echo   Password: Personal Access Token co quyen write_registry (KHONG dung mat khau GitLab)
docker login registry.gitlab.com
if errorlevel 1 (echo Dang nhap that bai & pause & exit /b 1)
echo ===== push %DATE% %TIME% ===== > "%LOG%"
echo ===== build lai (dung cache) ===== >> "%LOG%"
set DOCKER_BUILDKIT=1
docker build -f security-config\semgrep\ci\Dockerfile -t %LOCAL% . >> "%LOG%" 2>&1
echo build exit: %ERRORLEVEL% >> "%LOG%"
if errorlevel 1 goto end
docker tag %LOCAL% %REMOTE% >> "%LOG%" 2>&1
docker push %REMOTE% >> "%LOG%" 2>&1
echo push exit: %ERRORLEVEL% >> "%LOG%"
docker image inspect %REMOTE% --format "{{index .RepoDigests 0}}" >> "%LOG%" 2>&1
:end
echo ===== XONG %DATE% %TIME% ===== >> "%LOG%"
type "%LOG%"
pause
