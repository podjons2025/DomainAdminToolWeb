<# 
�����Ӳ���
#>

# �����Ӻ���
function script:Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)
    $response = $context.Response
    $requestData = Read-RequestData $context
    $sessionId = [Guid]::NewGuid().ToString()
    $remoteSession = $null

    # ��֤�������
    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.domain) -or 
        [string]::IsNullOrEmpty($requestData.username) -or 
        [string]::IsNullOrEmpty($requestData.password)) {
        Send-JsonResponse $response 400 @{ 
            success = $false; 
            message = "���ṩ���û���������" 
        }
        return
    }

    try {
        # ������ƾ��
        $securePassword = ConvertTo-SecureString -String $requestData.password -AsPlainText -Force
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $requestData.username, $securePassword

        # ����Զ�̻Ự
        $remoteSession = New-PSSession -ComputerName $requestData.domain -Credential $credential -ErrorAction Stop
        Write-Host "[����] Զ�̻Ự�����ɹ���ID: $($remoteSession.Id)"

        # �ؼ��޸�����;����ȡ�������Ϣ
        $domainPartition = $null
        $domainInfo = $null

        # ����1������ͨ��Get-ADDomain��ȡ�����ȷ�����
        try {
            $domainInfo = Invoke-Command -Session $remoteSession -ScriptBlock { 
                Import-Module ActiveDirectory -ErrorAction Stop
                $domain = Get-ADDomain -ErrorAction Stop
                Write-Host "[Զ�̵���] Get-ADDomain���ص�DefaultPartition: $($domain.DefaultPartition)"
                return $domain
            } -ErrorAction Stop

            if (-not [string]::IsNullOrEmpty($domainInfo.DefaultPartition)) {
                $domainPartition = $domainInfo.DefaultPartition
                Write-Host "[����] ͨ��Get-ADDomain��ȡ������: $domainPartition"
            }
        }
        catch {
            Write-Warning "[����] ����1��ȡ����Ϣʧ��: $($_.Exception.Message)�����Ա�ѡ����..."
        }

        # ����2��������1ʧ�ܣ�ͨ��Get-ADRootDSE��ȡ����ѡ���������ɿ���
        if ([string]::IsNullOrEmpty($domainPartition)) {
            try {
                $rootDSE = Invoke-Command -Session $remoteSession -ScriptBlock { 
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $dse = Get-ADRootDSE -ErrorAction Stop
                    Write-Host "[Զ�̵���] Get-ADRootDSE���ص�defaultNamingContext: $($dse.defaultNamingContext)"
                    return $dse
                } -ErrorAction Stop

                if (-not [string]::IsNullOrEmpty($rootDSE.defaultNamingContext)) {
                    $domainPartition = $rootDSE.defaultNamingContext
                    Write-Host "[����] ͨ��Get-ADRootDSE��ȡ������: $domainPartition"
                }
            }
            catch {
                Write-Warning "[����] ����2��ȡ����Ϣʧ��: $($_.Exception.Message)"
            }
        }

        # ����3����ǰ���ֶ�ʧ�ܣ�����ͨ�������������죨���ѡ��
        if ([string]::IsNullOrEmpty($domainPartition)) {
            $domainParts = $requestData.domain -split '\.'
            if ($domainParts.Count -ge 2) {
                $domainPartition = "DC=" + ($domainParts -join ",DC=")
                Write-Host "[����] ͨ�����������������: $domainPartition�����ܲ�׼ȷ��������Ȩ�ޣ�"
            }
        }

        # ������֤������Ϣ
        if ([string]::IsNullOrEmpty($domainPartition)) {
            throw "���з������޷���ȡ�������Ϣ�����飺1.ADģ��Ȩ�� 2.����������� 3.�û����Ƿ�Ϊ�����Ա"
        }

        # ��֤Ĭ��OU·����ʹ�û�ȡ���ķ�����Ϣ��
        $defaultOU = "CN=Users,$domainPartition"
        Write-Host "[����] ������֤��OU·��: $defaultOU"
	
        $userCount = 0
        $groupCount = 0

        # Զ��ͳ���û�����
        $userCount = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($ouPath)
            Import-Module ActiveDirectory -ErrorAction Stop
            $users = Get-ADUser -Filter * -SearchBase $ouPath -ErrorAction SilentlyContinue
            return $users.Count
        } -ArgumentList $defaultOU -ErrorAction SilentlyContinue

        # Զ��ͳ��������
        $groupCount = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($ouPath)
            Import-Module ActiveDirectory -ErrorAction Stop
            $groups = Get-ADGroup -Filter * -SearchBase $ouPath -ErrorAction SilentlyContinue
            return $groups.Count
        } -ArgumentList $defaultOU -ErrorAction SilentlyContinue

        # �洢�Ự��Ϣ������ userCountStatus/groupCountStatus ��ʼ����
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
            userCountStatus = $userCount  # ��ʼ���û�����
            groupCountStatus = $groupCount # ��ʼ�������
        }

        # ���ûỰCookie
        $cookie = New-Object System.Net.Cookie("SessionId", $sessionId)
        $cookie.Expires = [DateTime]::Now.AddHours(1)
        $context.Response.Cookies.Add($cookie)

        # ���سɹ���Ӧ
        Send-JsonResponse $response 200 @{ 
            success = $true 
            sessionId = $sessionId
            connected = $true
            message = "�ɹ����ӵ���: $($requestData.domain)"
            domainInfo = $domainInfo | Select-Object Name, DNSRoot, Forest
            currentOU = $defaultOU
            userCount = $userCount  # ǰ�˿�ֱ�ӻ�ȡ��ʼ����
            groupCount = $groupCount # ǰ�˿�ֱ�ӻ�ȡ��ʼ����
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