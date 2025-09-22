<# 
���������Web������
#>

# ����Ƿ��Թ���Ա�������
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "���Թ���Ա������д˽ű�����ȷ��Web��������������" -ForegroundColor Red
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# ���ù���Ŀ¼
$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location $scriptDir

# ����Web������
try {
    Write-Host "�������������Web������..." -ForegroundColor Cyan
    . "$scriptDir/Backend/Core/WebServer.ps1"
    Start-WebServer -Prefix "http://localhost:8080/"
}
catch {
    Write-Host "����������ʧ��: $_" -ForegroundColor Red
    Read-Host "��������˳�..."
}