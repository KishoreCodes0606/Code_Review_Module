@echo off
title AI Code Review - Code Submission Module
echo ========================================================
echo Starting AI Code Review - Code Submission Module (UI)...
echo ========================================================
cd /d "%~dp0code-submission-ui"
npm run dev
pause
