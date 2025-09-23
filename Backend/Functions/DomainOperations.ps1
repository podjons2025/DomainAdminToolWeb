<# 
域连接操作
#>

# 初始化会话存储（替换全局变量）
$script:sessions = @{}  # 键：SessionId（GUID），值：会话状态字典

function Connect-ToDomain {
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
            }
            remoteSession = $remoteSession
            currentOU = "CN=Users,$($domainInfo.DefaultPartition)"  # 默认OU
            allUsersOU = $null
            userCountStatus = 0
            groupCountStatus = 0
            # 其他会话相关变量
        }

        # 设置会话Cookie
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $context.Response.Cookies.Add($cookie)

        # 返回成功响应
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            message = "成功连接到域: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "连接域失败: $errorMsg"
        }
    }
}

function Disconnect-FromDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
	$cookie = $context.Request.Cookies["SessionId"]
	$sessionId = if ($cookie) { $cookie.Value } else { $null }

    if (-not $sessionId -or -not $script:sessions.ContainsKey($sessionId)) {
        Send-JsonResponse $response 401 @{ success = $false; message = "会话不存在或已过期" }
        return
    }

    try {
        # 关闭远程会话
        $session = $script:sessions[$sessionId]
        if ($session.remoteSession) {
            Remove-PSSession $session.remoteSession -ErrorAction Stop
        }
        # 删除会话
        $script:sessions.Remove($sessionId)
        # 清除Cookie
        $context.Response.Cookies["SessionId"].Expires = [DateTime]::Now.AddDays(-1)
        
        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "已成功断开域连接"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "断开连接失败: $errorMsg"
        }
    }
}

function Get-ConnectionStatus {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
	$cookie = $context.Request.Cookies["SessionId"]
	$sessionId = if ($cookie) { $cookie.Value } else { $null }

    if ($sessionId -and $script:sessions.ContainsKey($sessionId)) {
        $session = $script:sessions[$sessionId]
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $true
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