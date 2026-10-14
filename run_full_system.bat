@echo off
title AI Code Review Platform - Full System Launcher
echo ========================================================
echo Starting AI Code Review Platform (Backend + Frontend)...
echo ========================================================

echo [1/2] Launching Python Validation API Server (Port 8000)...
start "Python API Server (Port 8000)" cmd /k "cd /d %~dp0 && python server.py"

timeout /t 2 /nobreak >nul

echo [2/2] Launching React + Vite Frontend (Port 5173)...
start "React Vite UI (Port 5173)" cmd /k "cd /d %~dp0code-submission-ui && npm run dev"

echo.
echo ========================================================
echo Platform is ready!
echo   * Developer Portal (UI) : http://localhost:5173
echo   * Backend REST API      : http://localhost:8000
echo ========================================================
