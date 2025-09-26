<# 
PowerShell轻量级Web服务器核心（兼容PS 5.1）
基于HttpListener实现，显式路由处理
#>

Add-Type -AssemblyName System.Web

# 全局变量
$script:httpListener = New-Object System.Net.HttpListener
$script:frontendPath = $null
$script:sessions = @{}
$script:routes = @{}

# ==============================================
# 导入业务模块（顶层script作用域）
# ==============================================
function Import-BusinessModules {
    [CmdletBinding()]
    param()

    # 确定当前脚本所在目录的绝对路径
    $functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "../Functions"
    $helpersDir = Join-Path -Path $PSScriptRoot -ChildPath "../Helpers"

    # 转换为绝对路径，避免相对路径问题
    $functionsDir = [System.IO.Path]::GetFullPath($functionsDir)
    $helpersDir = [System.IO.Path]::GetFullPath($helpersDir)
	
    # 新增：打印解析后的路径
    Write-Host "[调试] 解析的Functions路径: $($functionsDir)"
    Write-Host "[调试] 解析的Helpers路径: $($helpersDir)"	

    # 验证目录存在
    if (-not (Test-Path $functionsDir -PathType Container)) {
        throw "Functions目录不存在: $functionsDir"
    }
    if (-not (Test-Path $helpersDir -PathType Container)) {
        throw "Helpers目录不存在: $helpersDir"
    }

    # 导入核心模块（显式script作用域）
    try {
        Write-Host "[模块] 开始导入业务模块..."
        Write-Host "[模块] 函数目录: $functionsDir"
        Write-Host "[模块] 帮助目录: $helpersDir"

        # 导入功能模块（强制script作用域）
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "DomainOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "UserOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "GroupOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "OUOperations.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "Helpers.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "PinyinConverter.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "importExportUsers.ps1")

        # 验证核心函数是否存在（必须通过，否则服务器无法启动）
        $requiredFuncs = @(
            "Get-ConnectionStatus", "Connect-ToDomain", "Disconnect-FromDomain",
            "Get-OUList", "Create-OU", "Switch-OU",
            "Get-UserList", "Create-User", "Toggle-UserEnabled", "Filter-Users",
            "Get-GroupList", "Create-Group", "Add-UserToGroup", "Filter-Groups",
            "Read-RequestData"  
        )

        $missingFuncs = @()
        foreach ($func in $requiredFuncs) {
            if (-not (Get-Command -Name $func -CommandType Function -Scope Script -ErrorAction SilentlyContinue)) {
                $missingFuncs += $func
            }
        }

        if ($missingFuncs.Count -gt 0) {
            throw "以下核心函数缺失（检查对应.ps1文件）: $($missingFuncs -join ', ')"
        }

        Write-Host "[模块] 所有核心业务函数导入成功（script作用域）"
    }
    catch {
        Write-Error "[模块] 导入失败: $_"
        throw  # 终止服务器启动
    }
}

# ==============================================
# 读取请求数据
# ==============================================
function script:Read-RequestData {
    param([System.Net.HttpListenerContext]$context)

    try {
        $reader = New-Object System.IO.StreamReader($context.Request.InputStream)
        $data = $reader.ReadToEnd()
        $reader.Dispose()
        
        if (-not [string]::IsNullOrEmpty($data)) {
            return $data | ConvertFrom-Json
        }
        return $null
    }
    catch {
        Write-Error "读取请求数据失败: $_"
        return $null
    }
}

# ==============================================
# 前端目录解析
# ==============================================
function Resolve-FrontendPath {
    [CmdletBinding()]
    param()
    
    $rawPath = Join-Path -Path $PSScriptRoot -ChildPath "../../Frontend"
    $resolvedPath = [System.IO.Path]::GetFullPath($rawPath)
	
    
    if (Test-Path $resolvedPath -PathType Container) {
        Write-Host "[信息] 前端目录解析成功: $resolvedPath"
        return $resolvedPath
    }
    else {
        Write-Warning "[警告] 前端目录不存在，使用原始路径: $resolvedPath"
        return $resolvedPath
    }
}

# ==============================================
# URL权限配置
# ==============================================
function Configure-UrlAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$prefix
    )
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "请以管理员身份运行，否则无法配置URL端口权限"
    }
    
    try {
        $netshOutput = netsh http add urlacl url=$prefix user=Administrators 2>&1
        if ($LASTEXITCODE -ne 0 -and $netshOutput -notmatch "已存在") {
            Write-Warning "[警告] URL权限注册不完全，但继续尝试启动: $netshOutput"
        }
        else {
            Write-Host "[信息] URL权限配置成功: $prefix"
        }
    }
    catch {
        Write-Warning "[警告] URL权限配置失败（可能不影响本地测试）: $_"
    }
}

# ==============================================
# 启动服务器
# ==============================================
function Start-WebServer {
    [CmdletBinding()]
    param(
        [string]$prefix = "http://localhost:8080/"
    )

    # 1. 导入业务模块（必须第一步）
    try {
        Import-BusinessModules
    }
    catch {
        Write-Error "[致命] 模块导入失败，服务器无法启动: $_"
        return
    }

    # 2. 解析前端目录
    $script:frontendPath = Resolve-FrontendPath
    if (-not (Test-Path -Path $script:frontendPath -PathType Container)) {
        Write-Error "[致命错误] 前端目录不存在: $script:frontendPath"
        return
    }

    # 3. 配置URL权限
    try {
        Configure-UrlAcl -prefix $prefix
    }
    catch {
        Write-Error "[致命错误] 权限配置失败: $_"
        return
    }

    # 4. 启动监听器
    if (-not $script:httpListener.IsListening) {
        $script:httpListener.Prefixes.Clear()
        $script:httpListener.Prefixes.Add($prefix)

        try {
            $script:httpListener.Start()
            Write-Host "`n====================================="
            Write-Host "Web服务器已启动（PowerShell 5.1兼容）"
            Write-Host "访问地址: $prefix"
            Write-Host "前端目录: $script:frontendPath"
            Write-Host "按Ctrl+C停止服务器"
            Write-Host "=====================================`n"

            # 5. 处理请求
            while ($script:httpListener.IsListening) {
                try {
                    $context = $script:httpListener.GetContext()
                    Handle-Request -context $context
                }
                catch [System.Net.HttpListenerException] {
                    if ($_.Exception.Message -notmatch "操作已取消") {
                        Write-Error "[请求异常] HttpListener错误: $($_.Exception.Message)"
                    }
                }
                catch {
                    Write-Error "[请求异常] 未知错误: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Error "[致命错误] 服务器启动失败（端口可能被占用）: $($_.Exception.Message)"
            Write-Host "`n排查建议："
            Write-Host "1. 检查端口占用：netstat -ano | findstr :$([Uri]$prefix | Select-Object -ExpandProperty Port)"
            Write-Host "2. 结束占用进程：taskkill /F /PID 【占用进程ID】"
            Write-Host "3. 更换端口启动：Start-WebServer -Prefix http://localhost:8081/"
        }
    }
}

# ==============================================
# 停止服务器
# ==============================================
function Stop-WebServer {
    if ($script:httpListener.IsListening) {
        $script:httpListener.Stop()
        $script:httpListener.Close()
        Write-Host "`n[信息] Web服务器已停止"
    }
}

# ==============================================
# 请求处理与路由
# ==============================================
function Handle-Request {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerContext]$context
    )

    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.LocalPath
    $method = $request.HttpMethod
    $sessionId = $null
    
    # 获取会话ID
    $cookie = $context.Request.Cookies["SessionId"]
    if ($cookie) {
        $sessionId = $cookie.Value
    }

    Write-Host "[请求] $method $path (会话: $sessionId)"

    try {
        # 特殊处理断开连接请求，允许即使会话看似无效也执行
        if ($method -eq "POST" -and $path -eq "/api/disconnect") {
            script:Disconnect-FromDomain -context $context -sessionId $sessionId
            return
        }

        # 检查会话是否有效（对于需要连接的API）
        $requiresConnection = $path -like "/api/*" -and 
                             $path -ne "/api/connection-status" -and 
                             $path -ne "/api/connect"
        
        # 验证会话状态
        $isConnected = $false
        if (-not [string]::IsNullOrEmpty($sessionId) -and $script:sessions.ContainsKey($sessionId)) {
            $session = $script:sessions[$sessionId]
            $isConnected = $session.domainContext.IsConnected
        }

        # 状态检查与提示
        if ($requiresConnection -and -not $isConnected) {
            Send-JsonResponse $response 401 @{ 
                success = $false 
                connected = $false
                message = "请先连接到域" 
            }
            return
        }

        # 路由匹配（保持不变）
        if ($method -eq "GET" -and $path -eq "/api/connection-status") {
            script:Get-ConnectionStatus -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/connect") {
            script:Connect-ToDomain -context $context
        }
        elseif ($method -eq "GET" -and $path -eq "/api/ous") {
            script:Get-OUList -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/ous") {
            script:Create-OU -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/switch-ou") {
            script:Switch-OU -context $context
        }
        elseif ($method -eq "GET" -and $path -eq "/api/users") {
            script:Get-UserList -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/users") {
            script:Create-User -context $context
        }
        elseif ($method -eq "PUT" -and $path -eq "/api/users/enable") {
            script:Toggle-UserEnabled -context $context
        }
        elseif ($method -eq "GET" -and $path -like "/api/users/filter*") {
            script:Filter-Users -context $context
        }
        elseif ($method -eq "GET" -and $path -eq "/api/groups") {
            script:Get-GroupList -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/groups") {
            script:Create-Group -context $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/groups/add-user") {
            script:Add-UserToGroup -context $context
        }
        elseif ($method -eq "GET" -and $path -like "/api/groups/filter*") {
            script:Filter-Groups -context $context
        }
        elseif ($method -eq "GET") {
            Serve-StaticFile -context $context
        }
        else {
            Send-Response -response $response -statusCode 404 -content "未找到请求的资源"
        }
    }
    catch {
        Write-Error "[处理错误] $($_.Exception.Message)"
        Send-Response -response $response -statusCode 500 -content "服务器内部错误: $($_.Exception.Message)"
    }
    finally {
        $response.OutputStream.Flush()
        $response.Close()
    }
}



# ==============================================
# 静态文件服务
# ==============================================
function Serve-StaticFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerContext]$context
    )

    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.LocalPath

    $filePath = if ($path -eq "/" -or [string]::IsNullOrEmpty($path)) {
        Join-Path -Path $script:frontendPath -ChildPath "index.html"
    }
    else {
        Join-Path -Path $script:frontendPath -ChildPath $path.TrimStart('/')
    }

    if (Test-Path $filePath -PathType Leaf) {
        try {
            $content = Get-Content $filePath -Raw -Encoding UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)

            $response.ContentLength64 = $bytes.Length
            $response.ContentType = Get-ContentType -filePath $filePath
            $response.OutputStream.Write($bytes, 0, $bytes.Length)

            Write-Host "[响应] 200 OK: $filePath"
        }
        catch {
            Send-Response -response $response -statusCode 500 -content "无法读取文件: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "[响应] 404 未找到: $filePath"
        Send-Response -response $response -statusCode 404 -content "文件未找到: $path"
    }
}

# ==============================================
# 获取内容类型
# ==============================================
function Get-ContentType {
    [CmdletBinding()]
    param([string]$filePath)
    
    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    switch ($ext) {
        ".html" { return "text/html; charset=utf-8" }
        ".css" { return "text/css; charset=utf-8" }
        ".js" { return "application/javascript; charset=utf-8" }
        ".json" { return "application/json; charset=utf-8" }
        ".png" { return "image/png" }
        ".jpg" { return "image/jpeg" }
        ".gif" { return "image/gif" }
        default { return "application/octet-stream" }
    }
}

# ==============================================
# 发送响应
# ==============================================
function Send-Response {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerResponse]$response,
        [int]$statusCode = 200,
        [string]$content = "",
        [string]$contentType = "text/plain; charset=utf-8"
    )

    $response.StatusCode = $statusCode
    $response.ContentType = $contentType
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $response.ContentLength64 = $bytes.Length

    try {
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
        $response.OutputStream.Flush()
    }
    catch {
        Write-Warning "[响应警告] 写入失败: $($_.Exception.Message)"
    }
}

# ==============================================
# 发送JSON响应
# ==============================================
function script:Send-JsonResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerResponse]$response,
        [int]$statusCode = 200,
        [PSObject]$data
    )

    $json = $data | ConvertTo-Json -Depth 10 -ErrorAction Stop
    Send-Response -response $response -statusCode $statusCode -content $json -contentType "application/json; charset=utf-8"
}

# ==============================================
# 终止处理
# ==============================================
$exitHandler = {
    Stop-WebServer
    exit 0
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $exitHandler | Out-Null

