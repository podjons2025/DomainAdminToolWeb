<# 
�����Ӳ���
#>

# ��ʼ���Ự�洢���滻ȫ�ֱ�����
$script:sessions = @{}  # ����SessionId��GUID����ֵ���Ự״̬�ֵ�

function Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $requestData = Read-RequestData $context

    # ��֤�������
    if (-not $requestData -or (-not $requestData.domain) -or (-not $requestData.username) -or (-not $requestData.password)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩ���û���������" }
        return
    }

    try {
        # ����Ψһ�ỰID
        $sessionId = [guid]::NewGuid().ToString()
        
        # ����Զ�̻Ự
        $securePassword = ConvertTo-SecureString $requestData.password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($requestData.username, $securePassword)
        $remoteSession = New-PSSession -ComputerName $requestData.domain -Credential $credential -ErrorAction Stop

        # ��ȡ����Ϣ
        $domainInfo = Invoke-Command -Session $remoteSession -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }

        # �洢�Ự״̬
        $script:sessions[$sessionId] = @{
            domainContext = @{
                Domain = $requestData.domain
                Username = $requestData.username
                DomainInfo = $domainInfo
            }
            remoteSession = $remoteSession
            currentOU = "CN=Users,$($domainInfo.DefaultPartition)"  # Ĭ��OU
            allUsersOU = $null
            userCountStatus = 0
            groupCountStatus = 0
            # �����Ự��ر���
        }

        # ���ûỰCookie
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $context.Response.Cookies.Add($cookie)

        # ���سɹ���Ӧ
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            message = "�ɹ����ӵ���: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "������ʧ��: $errorMsg"
        }
    }
}

function Disconnect-FromDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
	$cookie = $context.Request.Cookies["SessionId"]
	$sessionId = if ($cookie) { $cookie.Value } else { $null }

    if (-not $sessionId -or -not $script:sessions.ContainsKey($sessionId)) {
        Send-JsonResponse $response 401 @{ success = $false; message = "�Ự�����ڻ��ѹ���" }
        return
    }

    try {
        # �ر�Զ�̻Ự
        $session = $script:sessions[$sessionId]
        if ($session.remoteSession) {
            Remove-PSSession $session.remoteSession -ErrorAction Stop
        }
        # ɾ���Ự
        $script:sessions.Remove($sessionId)
        # ���Cookie
        $context.Response.Cookies["SessionId"].Expires = [DateTime]::Now.AddDays(-1)
        
        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "�ѳɹ��Ͽ�������"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "�Ͽ�����ʧ��: $errorMsg"
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
            message = "δ���ӵ��κ���"
        }
    }
}