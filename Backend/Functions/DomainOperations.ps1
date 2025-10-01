<# 
域连接操作
#>

# 域连接函数
function script:Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $requestData = Read-RequestData $context
    $sessionId = [Guid]::NewGuid().ToString()
    $remoteSession = $null

    # 验证输入参数
    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.domain) -or 
        [string]::IsNullOrEmpty($requestData.username) -or 
        [string]::IsNullOrEmpty($requestData.password)) {
        Send-JsonResponse $response 400 @{ 
            success = $false; 
            message = "请提供域、用户名和密码" 
        }
        return
    }

    try {
        # 创建域凭据
        $securePassword = ConvertTo-SecureString -String $requestData.password -AsPlainText -Force
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $requestData.username, $securePassword

        # 建立远程会话
        $remoteSession = New-PSSession -ComputerName $requestData.domain -Credential $credential -ErrorAction Stop
        Write-Host "[调试] 远程会话创建成功，ID: $($remoteSession.Id)"

        # 关键修复：多途径获取域分区信息
        $domainPartition = $null
        $domainInfo = $null

        # 方法1：尝试通过Get-ADDomain获取（优先方法）
        try {
            $domainInfo = Invoke-Command -Session $remoteSession -ScriptBlock { 
                Import-Module ActiveDirectory -ErrorAction Stop
                $domain = Get-ADDomain -ErrorAction Stop
                Write-Host "[远程调试] Get-ADDomain返回的DefaultPartition: $($domain.DefaultPartition)"
                return $domain
            } -ErrorAction Stop

            if (-not [string]::IsNullOrEmpty($domainInfo.DefaultPartition)) {
                $domainPartition = $domainInfo.DefaultPartition
                Write-Host "[调试] 通过Get-ADDomain获取到分区: $domainPartition"
            }
        }
        catch {
            Write-Warning "[调试] 方法1获取域信息失败: $($_.Exception.Message)，尝试备选方法..."
        }

        # 方法2：若方法1失败，通过Get-ADRootDSE获取（备选方案，更可靠）
        if ([string]::IsNullOrEmpty($domainPartition)) {
            try {
                $rootDSE = Invoke-Command -Session $remoteSession -ScriptBlock { 
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $dse = Get-ADRootDSE -ErrorAction Stop
                    Write-Host "[远程调试] Get-ADRootDSE返回的defaultNamingContext: $($dse.defaultNamingContext)"
                    return $dse
                } -ErrorAction Stop

                if (-not [string]::IsNullOrEmpty($rootDSE.defaultNamingContext)) {
                    $domainPartition = $rootDSE.defaultNamingContext
                    Write-Host "[调试] 通过Get-ADRootDSE获取到分区: $domainPartition"
                }
            }
            catch {
                Write-Warning "[调试] 方法2获取域信息失败: $($_.Exception.Message)"
            }
        }

        # 方法3：若前两种都失败，尝试通过域名解析构造（最后备选）
        if ([string]::IsNullOrEmpty($domainPartition)) {
            $domainParts = $requestData.domain -split '\.'
            if ($domainParts.Count -ge 2) {
                $domainPartition = "DC=" + ($domainParts -join ",DC=")
                Write-Host "[调试] 通过域名解析构造分区: $domainPartition（可能不准确，建议检查权限）"
            }
        }

        # 最终验证分区信息
        if ([string]::IsNullOrEmpty($domainPartition)) {
            throw "所有方法均无法获取域分区信息，请检查：1.AD模块权限 2.域控制器配置 3.用户名是否为域管理员"
        }

        # 验证默认OU路径（使用获取到的分区信息）
        $defaultOU = "CN=Users,$domainPartition"
        Write-Host "[调试] 最终验证的OU路径: $defaultOU"
	
        $userCount = 0
        $groupCount = 0

        # 远程统计用户数量
        $userCount = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($ouPath)
            Import-Module ActiveDirectory -ErrorAction Stop
            $users = Get-ADUser -Filter * -SearchBase $ouPath -ErrorAction SilentlyContinue
            return $users.Count
        } -ArgumentList $defaultOU -ErrorAction SilentlyContinue

        # 远程统计组数量
        $groupCount = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($ouPath)
            Import-Module ActiveDirectory -ErrorAction Stop
            $groups = Get-ADGroup -Filter * -SearchBase $ouPath -ErrorAction SilentlyContinue
            return $groups.Count
        } -ArgumentList $defaultOU -ErrorAction SilentlyContinue

        # 存储会话信息（新增 userCountStatus/groupCountStatus 初始化）
        $script:sessions[$sessionId] = @{
            domainContext = @{
                Domain     = $requestData.domain
                Username   = $requestData.username
                DomainInfo = $domainInfo
                IsConnected = $true
            }
            remoteSession = $remoteSession
            currentOU     = $defaultOU
            allUsersOU    = $null
            userCountStatus = $userCount  # 初始化用户计数
            groupCountStatus = $groupCount # 初始化组计数
        }

        # 设置会话Cookie
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $cookie.Expires = [DateTime]::Now.AddHours(1)
        $context.Response.Cookies.Add($cookie)

        # 返回成功响应
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            connected = $true
            message = "成功连接到域: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
            currentOU = $defaultOU
            userCount = $userCount  # 前端可直接获取初始计数
            groupCount = $groupCount # 前端可直接获取初始计数
        }
    }
    catch {
        if ($remoteSession) {
            Remove-PSSession -Session $remoteSession -ErrorAction SilentlyContinue
        }
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