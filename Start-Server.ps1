<# 
启动域管理Web服务器
#>

# 检查是否以管理员身份运行
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "请以管理员身份运行此脚本，以确保Web服务器正常工作" -ForegroundColor Red
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# 设置工作目录
$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
Set-Location $scriptDir

# 启动Web服务器
try {
    Write-Host "正在启动域管理Web服务器..." -ForegroundColor Cyan
    . "$scriptDir/Backend/Core/WebServer.ps1"
    Start-WebServer -Prefix "http://localhost:8080/"
}
catch {
    Write-Host "服务器启动失败: $_" -ForegroundColor Red
    Read-Host "按任意键退出..."
}