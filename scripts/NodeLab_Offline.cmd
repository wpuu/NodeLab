@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 goto use_python
py -3 "%~dp0nodelab_offline.pyw"
if errorlevel 1 pause
exit /b
:use_python
where python >nul 2>&1
if errorlevel 1 goto missing
python "%~dp0nodelab_offline.pyw"
if errorlevel 1 pause
exit /b
:missing
echo Python 3.12+ with Tk is required. No automatic install was performed.
pause
exit /b 2
