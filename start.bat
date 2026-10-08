@echo off
title Mini SIEM & WAF Host Defense
echo ===================================================
echo   Starting Mini-SIEM Dashboard & Defense Engine...
echo ===================================================
echo.

echo [*] Checking and installing required packages...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo [!] Error: Python or pip is not found in PATH!
    echo [!] Please install Python and check 'Add Python to PATH'.
    pause
    exit /b
)

echo [*] Launching Browser Dashboard...
start http://127.0.0.1:5000

echo [*] Running Web Defense Server on http://127.0.0.1:5000
echo [*] Press CTRL+C to stop the server anytime.
echo.
python server.py
pause