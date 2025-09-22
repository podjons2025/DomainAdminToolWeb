<# 
域连接操作
#>

# 全局状态变量
$script:domainContext = $null
$script:remoteSession = $null
$script:currentOU = $null
$script:allUsersOU = $null
$script:allUsers = New-Object System.Collections.ArrayList
$script:allGroups = New-Object System.Collections.ArrayList
$script:connectionStatus = "未连接到域"
$script:userCountStatus = "0"
$script:groupCountStatus = "0"

function Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $requestData -or -not $requestData.domain -or -not $requestData.adminUser -or -not $requestData.adminPassword) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供域地址、管理员账号和密码" }
        return
    }

    try {
        $domain = $requestData.domain
        $adminUser = $requestData.adminUser
        $adminPassword = $requestData.adminPassword

        # 创建安全密码
        $securePassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($adminUser, $securePassword)
        
        # 创建远程会话
        $script:remoteSession = New-PSSession -ComputerName $domain -Credential $credential -ErrorAction Stop
        $script:connectionStatus = "正在验证远程服务器AD服务..."

        # 远程验证AD模块
        $domainInfo = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            return Get-ADDomain -ErrorAction Stop
        } -ErrorAction Stop
        
        $script:domainContext = @{
            Server = $domain
            Credential = $credential
            DomainInfo = $domainInfo
        }
        
        # 设置默认OU
        $script:currentOU = "CN=Users,$($domainInfo.DefaultPartition)"
        
        $script:connectionStatus = "已连接到域: $domain"
        
        # 加载用户和组列表
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "连接成功"
            domainInfo = @{
                Name = $domainInfo.Name
                DNSRoot = $domainInfo.DNSRoot
                DefaultPartition = $domainInfo.DefaultPartition
            }
            currentOU = $script:currentOU
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "WinRM") { 
            $errorMsg += "`n请确保远程服务器已启用WinRM服务，可以运行winrm quickconfig配置" 
        }
        elseif ($errorMsg -match "ActiveDirectory") { 
            $errorMsg += "`n请确保远程服务器已安装AD模块" 
        }
        
        $script:connectionStatus = "连接失败: $errorMsg"
        $script:domainContext = $null
        $script:remoteSession = $null
        
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = $errorMsg
        }
    }
}

function Disconnect-FromDomain {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    $script:domainContext = $null
    $script:allUsers.Clear()
    $script:allGroups.Clear()
    $script:allOUs = $null
    $script:currentOU = $null
    
    # 关闭远程会话
    if ($script:remoteSession) {
        Remove-PSSession $script:remoteSession
        $script:remoteSession = $null
    }

    $script:connectionStatus = "未连接到域"
    $script:userCountStatus = "0"
    $script:groupCountStatus = "0"

    Send-JsonResponse $response 200 @{ 
        success = $true 
        message = "已成功断开连接"
    }
}

function Get-ConnectionStatus {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    
    $isConnected = $null -ne $script:domainContext
    
    Send-JsonResponse $response 200 @{ 
        isConnected = $isConnected
        status = $script:connectionStatus
        currentOU = $script:currentOU
        userCount = $script:userCountStatus
        groupCount = $script:groupCountStatus
    }
}