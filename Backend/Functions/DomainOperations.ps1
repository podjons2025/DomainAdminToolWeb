<# 
�����Ӳ��� - �޸���
#>

# �����Ӻ���
function script:Connect-ToDomain {
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
                IsConnected = $true  # ��ȷ���Ϊ������
            }
            remoteSession = $remoteSession
            currentOU = "CN=Users,$($domainInfo.DefaultPartition)"  # Ĭ��OU
            allUsersOU = $null
            userCountStatus = 0
            groupCountStatus = 0
        }

        # ���ûỰCookie���ӳ���Ч��
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $cookie.Expires = [DateTime]::Now.AddHours(1)  # �Ự��Ч��1Сʱ
        $context.Response.Cookies.Add($cookie)

        # ���سɹ���Ӧ
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            connected = $true  # ��ȷ��������״̬
            message = "�ɹ����ӵ���: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            connected = $false
            message = "������ʧ��: $errorMsg"
        }
    }
}

# �Ͽ������Ӻ���
function script:Disconnect-FromDomain {
    param(
        [System.Net.HttpListenerContext]$context,
        [string]$sessionId  # ��Handle-Requestֱ�Ӵ��ݻỰID
    )
    
    $response = $context.Response
    
    # ���δ�Ӳ�����ȡ�ỰID�����Դ�Cookie��ȡ
    if ([string]::IsNullOrEmpty($sessionId)) {
        $cookie = $context.Request.Cookies["SessionId"]
        $sessionId = if ($cookie) { $cookie.Value } else { $null }
    }

    Write-Host "[����] ���ԶϿ����� - �ỰID: $sessionId"

    # ��ʹ�ỰID�����ڻ���Ч��Ҳ�������Cookie
    try {
        # ���Cookie�����ۻỰ�Ƿ���ڣ�
        $cookie = New-Object System.Net.Cookie("SessionId", "")
        $cookie.Expires = [DateTime]::Now.AddDays(-1)
        $context.Response.Cookies.Add($cookie)
        Write-Host "[����] �����SessionId Cookie"
    }
    catch {
        Write-Warning "[����] ���Cookieʧ��: $($_.Exception.Message)"
    }

    # ����ʵ�ʵĻỰ�Ͽ�
    if (-not $sessionId -or -not $script:sessions.ContainsKey($sessionId)) {
        Write-Host "[����] �Ự�����ڻ��ѹ���: $sessionId"
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $false
            message = "�ѶϿ����ӣ��Ự�����ڻ��ѹ��ڣ�" 
        }
        return
    }

    try {
        # ��ȡ�Ự���ر�Զ������
        $session = $script:sessions[$sessionId]
        Write-Host "[����] �ҵ��Ự�����Թر�Զ������: $sessionId"
        
        # �ر�Զ�̻Ự����ӳ�ʱ�ʹ�����
        if ($session.remoteSession) {
            $sessionClosed = $false
            $timeout = 5000  # 5�볬ʱ
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            # ���ԹرջỰ
            while (-not $sessionClosed -and $stopwatch.ElapsedMilliseconds -lt $timeout) {
                try {
                    Remove-PSSession $session.remoteSession -ErrorAction Stop
                    $sessionClosed = $true
                    Write-Host "[����] Զ�̻Ự�ѹر�: $($session.remoteSession.Id)"
                }
                catch {
                    Write-Warning "[����] �ر�Զ�̻Ựʧ�ܣ�������: $($_.Exception.Message)"
                    Start-Sleep -Milliseconds 500
                }
            }
            
            if (-not $sessionClosed) {
                Write-Warning "[����] �ر�Զ�̻Ự��ʱ"
            }
        }
        
        # ǿ�ƴӻỰ�������Ƴ�
        $removed = $script:sessions.Remove($sessionId)
        if ($removed) {
            Write-Host "[����] �Ự�ѴӼ������Ƴ�: $sessionId"
        } else {
            Write-Warning "[����] �Ựδ�Ӽ������ҵ�: $sessionId"
        }
        
        Send-JsonResponse $response 200 @{ 
            success = $true 
            connected = $false
            message = "�ѳɹ��Ͽ�������"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "[����] �Ͽ����ӹ����з�������: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "�Ͽ�����ʧ��: $errorMsg"
        }
    }
}




# ��ȡ����״̬���� - �޸���
function script:Get-ConnectionStatus {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $cookie = $context.Request.Cookies["SessionId"]
    $sessionId = if ($cookie) { $cookie.Value } else { $null }

    # ���Ự�Ƿ��������Ч
    if ($sessionId -and $script:sessions.ContainsKey($sessionId)) {
        $session = $script:sessions[$sessionId]
        # ��֤Զ�̻Ự�Ƿ���Ȼ��Ч
        $sessionValid = $false
        try {
            if ($session.remoteSession) {
                # ���Ի�ȡ�Ự״̬
                $sessionState = Get-PSSession -Id $session.remoteSession.Id -ErrorAction Stop
                $sessionValid = $sessionState.State -eq 'Opened'
            }
        }
        catch {
            $sessionValid = $false
        }
        
        # ����Ự��Ч������״̬
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
            message = "δ���ӵ��κ���"
        }
    }
} 