<# 
域连接操作 - 修复版
#>

# 域连接函数
function script:Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $requestData = Read-RequestData $context

    # 验证输入参数
    if (-not $requestData -or (-not $requestData.domain) -or (-not $requestData.username) -or (-not $requestData.password)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供域、用户名和密码" }
        return
    }

    try {
        # 生成唯一会话ID
        $sessionId = [guid]::NewGuid().ToString()
        
        # 创建远程会话
        $securePassword = ConvertTo-SecureString $requestData.password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($requestData.username, $securePassword)
        $remoteSession = New-PSSession -ComputerName $requestData.domain -Credential $credential -ErrorAction Stop

        # 获取域信息
        $domainInfo = Invoke-Command -Session $remoteSession -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }

        # 存储会话状态
        $script:sessions[$sessionId] = @{
            domainContext = @{
                Domain = $requestData.domain
                Username = $requestData.username
                DomainInfo = $domainInfo
                IsConnected = $true  # 明确标记为已连接
            }
            remoteSession = $remoteSession
            currentOU = "CN=Users,$($domainInfo.DefaultPartition)"  # 默认OU
            allUsersOU = $null
            userCountStatus = 0
            groupCountStatus = 0
        }

        # 设置会话Cookie，延长有效期
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $cookie.Expires = [DateTime]::Now.AddHours(1)  # 会话有效期1小时
        $context.Response.Cookies.Add($cookie)

        # 返回成功响应
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            connected = $true  # 明确返回连接状态
            message = "成功连接到域: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            connected = $false
            message = "连接域失败: $errorMsg"
        }
    }
}

# 断开域连接函数
function script:Disconnect-FromDomain {
    param(
        [System.Net.HttpListenerContext]$context,
        [string]$sessionId  # 从Handle-Request直接传递会话ID
    )
    
    $response = $context.Response
    
    # 如果未从参数获取会话ID，则尝试从Cookie获取
    if ([string]::IsNullOrEmpty($sessionId)) {
        $cookie = $context.Request.Cookies["SessionId"]
        $sessionId = if ($cookie) { $cookie.Value } else { $null }
    }

    Write-Host "[调试] 尝试断开连接 - 会话ID: $sessionId"

    # 即使会话ID不存在或无效，也尝试清除Cookie
    try {
        # 清除Cookie（无论会话是否存在）
        $cookie = New-Object System.Net.Cookie("SessionId", "")
        $cookie.Expires = [DateTime]::Now.AddDays(-1)
        $context.Response.Cookies.Add($cookie)
        Write-Host "[调试] 已清除SessionId Cookie"
    }
    catch {
        Write-Warning "[警告] 清除Cookie失败: $($_.Exception.Message)"
    }

    # 处理实际的会话断开
    if (-not $sessionId -or -not $script:sessions.ContainsKey($sessionId)) {
        Write-Host "[调试] 会话不存在或已过期: $sessionId"
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $false
            message = "已断开连接（会话不存在或已过期）" 
        }
        return
    }

    try {
        # 获取会话并关闭远程连接
        $session = $script:sessions[$sessionId]
        Write-Host "[调试] 找到会话，尝试关闭远程连接: $sessionId"
        
        # 关闭远程会话（添加超时和错误处理）
        if ($session.remoteSession) {
            $sessionClosed = $false
            $timeout = 5000  # 5秒超时
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # 尝试关闭会话
            while (-not $sessionClosed -and $stopwatch.ElapsedMilliseconds -lt $timeout) {
                try {
                    Remove-PSSession $session.remoteSession -ErrorAction Stop
                    $sessionClosed = $true
                    Write-Host "[调试] 远程会话已关闭: $($session.remoteSession.Id)"
                }
                catch {
                    Write-Warning "[警告] 关闭远程会话失败，将重试: $($_.Exception.Message)"
                    Start-Sleep -Milliseconds 500
                }
            }
            
            if (-not $sessionClosed) {
                Write-Warning "[警告] 关闭远程会话超时"
            }
        }
        
        # 强制从会话集合中移除
        $removed = $script:sessions.Remove($sessionId)
        if ($removed) {
            Write-Host "[调试] 会话已从集合中移除: $sessionId"
        } else {
            Write-Warning "[警告] 会话未从集合中找到: $sessionId"
        }
        
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $false
            message = "已成功断开域连接"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "[错误] 断开连接过程中发生错误: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "断开连接失败: $errorMsg"
        }
    }
}




# 获取连接状态函数 - 修复版
function script:Get-ConnectionStatus {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $cookie = $context.Request.Cookies["SessionId"]
    $sessionId = if ($cookie) { $cookie.Value } else { $null }

    # 检查会话是否存在且有效
    if ($sessionId -and $script:sessions.ContainsKey($sessionId)) {
        $session = $script:sessions[$sessionId]
        # 验证远程会话是否仍然有效
        $sessionValid = $false
        try {
            if ($session.remoteSession) {
                # 尝试获取会话状态
                $sessionState = Get-PSSession -Id $session.remoteSession.Id -ErrorAction Stop
                $sessionValid = $sessionState.State -eq 'Opened'
            }
        }
        catch {
            $sessionValid = $false
        }
        
        # 如果会话无效，更新状态
        if (-not $sessionValid) {
            $session.domainContext.IsConnected = $false
            $script:sessions[$sessionId] = $session
        }
        
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $session.domainContext.IsConnected
            domain = $session.domainContext.Domain
            currentOU = $session.currentOU
            userCount = $session.userCountStatus
            groupCount = $session.groupCountStatus
        }
    }
    else {
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $false
            message = "未连接到任何域"
        }
    }
} 