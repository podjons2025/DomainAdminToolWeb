<# 
�û���������
#>

# ע�⣺���к���������� script: ǰ׺��ȷ���ڽű��������ж���

function script:LoadUserList {
    if (-not $script:domainContext) {
        return
    }

    try {
        $script:connectionStatus = "���ڼ��� OU: $($script:currentOU) �е��û�..."
        
        $script:allUsers.Clear()

        # Զ�̼����û�
        $remoteUsers = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($searchBase, $allUsersOU)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            if ($allUsersOU) {
                $users = Get-ADUser -Filter * -Properties DisplayName, SamAccountName, MemberOf, EmailAddress, TelephoneNumber, LockedOut, Description, Enabled, AccountExpirationDate -ErrorAction Stop
            }
            else {
                # ʹ�� -SearchBase ����ֻ��ѯָ��OU�е��û�
                $users = Get-ADUser -Filter * -SearchBase $searchBase `
                    -Properties DisplayName, SamAccountName, MemberOf, EmailAddress, TelephoneNumber, LockedOut, Description, Enabled, AccountExpirationDate `
                    -ErrorAction Stop
            }

            $users | ForEach-Object {
                $groupNames = $_.MemberOf | ForEach-Object { if ($_ -match 'CN=([^,]+)') { $matches[1] } }
                $groupsString = if ($groupNames) { $groupNames -join ', ' } else { '��' }
                [PSCustomObject]@{
                    DisplayName          = $_.DisplayName
                    SamAccountName       = $_.SamAccountName
                    MemberOf             = $groupsString
                    EmailAddress         = $_.EmailAddress
                    TelePhone            = $_.TelephoneNumber
                    AccountLockout       = [bool]$_.LockedOut
                    Description          = $_.Description
                    Enabled              = [bool]$_.Enabled
                    AccountExpirationDate = $_.AccountExpirationDate
                }
            }			
        } -ArgumentList $script:currentOU, $script:allUsersOU -ErrorAction Stop

        $remoteUsers | ForEach-Object { $script:allUsers.Add($_) | Out-Null }
        
        $script:userCountStatus = $script:allUsers.Count
        $script:connectionStatus = "�Ѽ��� OU: $($script:currentOU) �е� $($script:userCountStatus) ���û�"
    }
    catch {
        $script:connectionStatus = "�����û�ʧ��: $($_.Exception.Message)"
        Write-Error $_.Exception.Message
    }
}

function script:Get-UserList {
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerContext]$context
    )

    $response = $context.Response
    $sessionId = $null
    $session = $null

    try {
        # 1. ��ȡ����֤�ỰID
        $cookie = $context.Request.Cookies["SessionId"]
        if (-not $cookie -or [string]::IsNullOrEmpty($cookie.Value)) {
            Send-JsonResponse $response 401 @{
                success = $false
                connected = $false
                message = "δ��⵽�Ự�����������ӵ���"
            }
            return
        }
        $sessionId = $cookie.Value

        # 2. ��֤�Ự������
        if (-not $script:sessions.ContainsKey($sessionId)) {
            Send-JsonResponse $response 401 @{
                success = $false
                connected = $false
                message = "�Ự�ѹ��ڻ���Ч������������"
            }
            return
        }
        $session = $script:sessions[$sessionId]

        # 3. ��֤������״̬
        if (-not $session.domainContext.IsConnected -or -not $session.remoteSession) {
            Send-JsonResponse $response 400 @{
                success = $false
                connected = $false
                message = "�������ӵ���"
            }
            return
        }

        # 4. ������ҳ����������PS 5.1�Ĳ�ѯ�ַ�������
        $query = [System.Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)
        $page = if (-not [string]::IsNullOrEmpty($query["page"])) { [int]$query["page"] } else { 1 }
        $pageSize = if (-not [string]::IsNullOrEmpty($query["pageSize"])) { [int]$query["pageSize"] } else { 20 }

        # ��֤��ҳ������Ч��
        if ($page -lt 1) { $page = 1 }
        if ($pageSize -lt 1 -or $pageSize -gt 100) { $pageSize = 20 }

        # 5. �ӻỰ��ȡ��Ҫ��Ϣ
        $remoteSession = $session.remoteSession
        $currentOU = $session.currentOU
        $domainInfo = $session.domainContext.DomainInfo

        # 6. ��֤OU·����Ч�ԣ����"��������"���⣩
        $ouValidation = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($ouPath)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # ���OU�Ƿ����
            $ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'" -ErrorAction SilentlyContinue
            if ($ou) { return $true }
            
            # ����Ƿ�Ϊ������������CN=Users��
            $container = Get-ADObject -Filter "DistinguishedName -eq '$ouPath'" -ErrorAction SilentlyContinue
            return $null -ne $container
        } -ArgumentList $currentOU -ErrorAction Stop

        if (-not $ouValidation) {
            Send-JsonResponse $response 400 @{
                success = $false
                message = "��ǰOU·����Ч���޷���Ȩ��: $currentOU"
            }
            return
        }

        # 7. Զ�̲�ѯAD�û���PowerShell 5.1�����﷨��
        $allUsers = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($searchBase, $domainDNS)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # ִ��AD��ѯ��������Ҫ���ԣ�
            $users = Get-ADUser -Filter * -SearchBase $searchBase `
                -Properties DisplayName, EmailAddress, TelephoneNumber, 
                            Description, Enabled, MemberOf, SamAccountName `
                -ErrorAction Stop

            # �����û����ݣ�ת������ϢΪ�Ѻ����ƣ�
            $users | ForEach-Object {
                $groupNames = @()
                if ($_.MemberOf) {
                    $groupNames = $_.MemberOf | ForEach-Object {
                        if ($_ -match 'CN=([^,]+)') { $matches[1] }
                    }
                }

                # ����PS 5.1���ݵ��Զ������
                [PSCustomObject]@{
                    DisplayName      = $_.DisplayName
                    SamAccountName   = $_.SamAccountName
                    EmailAddress     = $_.EmailAddress
                    TelephoneNumber  = $_.TelephoneNumber
                    Description      = $_.Description
                    Enabled          = [bool]$_.Enabled
                    MemberOf         = $groupNames -join '; '
                }
            }
        } -ArgumentList $currentOU, $domainInfo.DNSRoot -ErrorAction Stop

        # 8. ִ�з�ҳ����
        $totalUsers = $allUsers.Count
        $skipCount = ($page - 1) * $pageSize
        $pagedUsers = $allUsers | Select-Object -Skip $skipCount -First $pageSize

        # 9. ���»Ự�е��û�����
        $session.userCountStatus = $totalUsers
        $script:sessions[$sessionId] = $session

        # 10. ���سɹ���Ӧ
        Send-JsonResponse $response 200 @{
            success = $true
            connected = $true
            users = $pagedUsers
            total = $totalUsers
            page = $page
            pageSize = $pageSize
            currentOU = $currentOU
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "[Get-UserList ����] $errorMsg"
        
        # ���ݻỰ״̬�����ʵ�������״̬
        $isConnected = if ($session) { $session.domainContext.IsConnected } else { $false }
        
        Send-JsonResponse $response 500 @{
            success = $false
            connected = $isConnected
            message = "��ȡ�û��б�ʧ��: $errorMsg"
        }
    }
}




function script:Create-User {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
	$cookie = $context.Request.Cookies["SessionId"]
	$sessionId = if ($cookie) { $cookie.Value } else { $null }
    $requestData = Read-RequestData $context

    if (-not $sessionId -or -not $script:sessions.ContainsKey($sessionId)) {
        Send-JsonResponse $response 401 @{ success = $false; message = "�Ự�ѹ���" }
        return
    }
	 $session = $script:sessions[$sessionId]
    if ($passwordErrors.Count -gt 0) {
        Send-JsonResponse $response 400 @{ 
            success = $false 
            message = "���벻����Ҫ��: $($passwordErrors -join '; ')"
        }
        return
    }	 
    # ��֤�����ֶ�
    $requiredFields = @('cnName', 'username', 'password', 'confirmPassword')
    foreach ($field in $requiredFields) {
        if (-not $requestData.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace($requestData.$field)) {
            Send-JsonResponse $response 400 @{ success = $false; message = "����д������Ϣ: $field" }
            return
        }
    }

    # ��֤����һ����
    if ($requestData.password -ne $requestData.confirmPassword) {
        Send-JsonResponse $response 400 @{ success = $false; message = "������������벻һ��" }
        return
    }

    # ��֤���븴�Ӷ�
    if ($requestData.password.Length -lt 8 -or 
        $requestData.password -notmatch '[A-Z]' -or 
        $requestData.password -notmatch '[a-z]' -or 
        $requestData.password -notmatch '[0-9]' -or 
        $requestData.password -notmatch '[^a-zA-Z0-9]') {
        Send-JsonResponse $response 400 @{ 
            success = $false 
            message = "�����������8λ��������Сд��ĸ�����ֺ������ַ�(��@#$)" 
        }
        return
    }

    try {
        $cnName = $requestData.cnName.Trim()
        $username = $requestData.username.Trim()
        $email = $requestData.email.Trim()
        $phone = $requestData.phone.Trim()
        $description = $requestData.description.Trim()
        $password = $requestData.password
        $neverExpire = $requestData.neverExpire -eq $true
        $currentOU = $script:currentOU
        $domainDNSRoot = $script:domainContext.DomainInfo.DNSRoot

        if ([string]::IsNullOrEmpty($email)) {
            $email = "$username@$domainDNSRoot"
        }

        $script:connectionStatus = "���ڴ����û� [$username]..."

        # Զ�̴����û�
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($cn, $samAccountName, $email, $phone, $desc, $pass, $ou, $domainDNS, $neverExpire)
            
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $securePass = ConvertTo-SecureString $pass -AsPlainText -Force
            
            $userParams = @{
                Name              = $cn
                GivenName         = $cn
                SamAccountName    = $samAccountName
                UserPrincipalName = "$samAccountName@$domainDNS"
                EmailAddress      = $email
                OfficePhone       = $phone
                Description       = $desc
                AccountPassword   = $securePass
                Enabled           = $true
                Path              = $ou
                ChangePasswordAtLogon = $false
                PasswordNeverExpires = $neverExpire
            }
            
            New-ADUser @userParams -ErrorAction Stop
            return Get-ADUser -Identity $samAccountName -Properties *
        } -ArgumentList $cnName, $username, $email, $phone, $description, $password, $currentOU, $domainDNSRoot, $neverExpire -ErrorAction Stop

        # ���¼����û��б�
        LoadUserList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "�û� [$username] �����ɹ�"
            userCount = $script:userCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "�����û�ʧ��: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "�����û�ʧ��: $errorMsg"
        }
    }
}

function script:Toggle-UserEnabled {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.username) -or $requestData.newState -eq $null) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩ�û����Ͳ���״̬" }
        return
    }

    try {
        $username = $requestData.username.Trim()
        $newState = $requestData.newState
        $action = if ($newState) { "����" } else { "����" }

        $script:connectionStatus = "����$action�û� [$username]..."

        # Զ��ִ������/���ò���
        $remoteResult = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($user, $state)
            Import-Module ActiveDirectory -ErrorAction Stop
            $adUser = Get-ADUser -Filter { SamAccountName -eq $user } -ErrorAction Stop
            Set-ADUser -Identity $adUser.DistinguishedName -Enabled $state -ErrorAction Stop
            $updatedUser = Get-ADUser -Identity $adUser.DistinguishedName -Properties Enabled -ErrorAction Stop
            return $updatedUser.Enabled
        } -ArgumentList $username, $newState -ErrorAction Stop

        if ($remoteResult -ne $newState) {
            throw "�û�״̬����ʧ��"
        }

        # ���¼����û��б�
        LoadUserList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "�û� [$username] $action�ɹ�"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $action = if ($requestData.newState) { "����" } else { "����" }
        $script:connectionStatus = "${action}�û�ʧ��: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "${action}�û�ʧ��: $errorMsg"
        }
    }
}

function script:Filter-Users {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $filterText = $context.Request.QueryString["filter"]

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    try {
        if ([string]::IsNullOrEmpty($filterText)) {
            $filteredUsers = $script:allUsers
        }
        else {
            $lowerFilter = $filterText.ToLower()
            $filteredUsers = @($script:allUsers | Where-Object {
                ( (-not [string]::IsNullOrEmpty($_.DisplayName)) -and $_.DisplayName.ToLower() -like "*$lowerFilter*" ) -or
                $_.SamAccountName.ToLower() -like "*$lowerFilter*" -or
                ( (-not [string]::IsNullOrEmpty($_.EmailAddress)) -and $_.EmailAddress.ToLower() -like "*$lowerFilter*" ) -or
                ( (-not [string]::IsNullOrEmpty($_.TelePhone)) -and $_.TelePhone.ToLower() -like "*$lowerFilter*" ) -or
                ( (-not [string]::IsNullOrEmpty($_.Description)) -and $_.Description.ToLower() -like "*$lowerFilter*" ) -or
                ( (-not [string]::IsNullOrEmpty($_.MemberOf)) -and $_.MemberOf.ToLower() -like "*$lowerFilter*" )
            })
        }

        Send-JsonResponse $response 200 @{ 
            success = $true 
            users = $filteredUsers
            count = $filteredUsers.Count
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "ɸѡ�û�ʧ��: $errorMsg"
        }
    }
}
