@echo off
setlocal enabledelayedexpansion

set "current_dir=%~dp0"
set "script_name=StartServer.ps1"

:: ���ű��Ƿ����
if not exist "%current_dir%%script_name%" (
    echo ����δ�ҵ� %script_name%
    echo ��ȷ���������ļ���PowerShell�ű���ͬһĿ¼
    pause
    exit /b 1
)

:: Ȩ�޼��
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo �����������ԱȨ��...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ִ�нű�
echo ���Ժ򡣡��������ڼ��� %script_name%...
cd /d "%current_dir%"
powershell.exe -ExecutionPolicy Bypass -File "%script_name%"

if %errorLevel% equ 0 (
    echo �ű�ִ�гɹ���
) else (
    echo �ű�ִ��ʧ�ܣ��������: %errorLevel%
)

exit 1
