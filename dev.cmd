@echo off
setlocal

REM Runs the full dev stack (FastAPI + React UI) using PowerShell script.
REM Usage:
REM   dev.cmd

set ROOT=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%dev.ps1"

endlocal
