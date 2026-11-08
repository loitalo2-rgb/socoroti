@echo off
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m socoroti %*
    exit /b %errorlevel%
)

where python >nul 2>nul
if %errorlevel%==0 (
    python -m socoroti %*
    exit /b %errorlevel%
)

echo.
echo  SocorroTI precisa do Python 3.9 ou superior.
echo  Baixe em: https://www.python.org/downloads/windows/
echo  Marque a opcao "Add Python to PATH" durante a instalacao.
echo.
pause
exit /b 1
