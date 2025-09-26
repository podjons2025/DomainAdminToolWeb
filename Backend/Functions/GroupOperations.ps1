<# 
���������
#>

# ע�⣺���к���������� script: ǰ׺��ȷ���ڽű��������ж���

function script:LoadGroupList {
    if (-not $script:domainContext) {
        return
    }

    try {
        $script:connectionStatus = "���ڼ��� OU: $($script:currentOU) �е���..."
        
        $script:allGroups.Clear()

        # Զ�̼�����
        $remoteGroups = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($searchBase, $allUsersOU)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            if ($allUsersOU) {
                Get-ADGroup -Filter * `
                    -Properties Name, SamAccountName, Description `
                    | Select-Object Name, SamAccountName, Description				
            }
            else {
                # ʹ�� -SearchBase ����ֻ��ѯָ��OU�е���
                Get-ADGroup -Filter * -SearchBase $searchBase `
                    -Properties Name, SamAccountName, Description `
                    | Select-Object Name, SamAccountName, Description
            }
        } -ArgumentList $script:currentOU, $script:allUsersOU -ErrorAction Stop

        $remoteGroups | ForEach-Object { $script:allGroups.Add($_) | Out-Null }
        
        $script:groupCountStatus = $script:allGroups.Count
        $script:connectionStatus = "�Ѽ��� OU: $($script:currentOU) �е� $($script:groupCountStatus) ����"
    }
    catch {
        $script:connectionStatus = "������ʧ��: $($_.Exception.Message)"
        Write-Error $_.Exception.Message
    }
}

function script:Get-GroupList {
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

        # 4. ������ҳ����������PS 5.1��
        $query = [System.Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)
        $page = if (-not [string]::IsNullOrEmpty($query["page"])) { [int]$query["page"] } else { 1 }
        $pageSize = if (-not [string]::IsNullOrEmpty($query["pageSize"])) { [int]$query["pageSize"] } else { 20 }

        # ��֤��ҳ������Ч��
        if ($page -lt 1) { $page = 1 }
        if ($pageSize -lt 1 -or $pageSize -gt 100) { $pageSize = 20 }

        # 5. �ӻỰ��ȡ��Ҫ��Ϣ
        $remoteSession = $session.remoteSession
        $currentOU = $session.currentOU
        $allUsersOU = $session.allUsersOU

        # 6. Զ�̲�ѯAD�飨PowerShell 5.1�����﷨��
        $allGroups = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($searchBase, $searchAll)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # ���ݲ���������ѯ��Χ
            if ($searchAll) {
                $groups = Get-ADGroup -Filter * `
                    -Properties Name, SamAccountName, Description, GroupScope `
                    -ErrorAction Stop
            }
            else {
                $groups = Get-ADGroup -Filter * -SearchBase $searchBase `
                    -Properties Name, SamAccountName, Description, GroupScope `
                    -ErrorAction Stop
            }

            # ����������
            $groups | ForEach-Object {
                [PSCustomObject]@{
                    Name              = $_.Name
                    SamAccountName    = $_.SamAccountName
                    Description       = $_.Description
                    GroupScope        = $_.GroupScope.ToString()
                    DistinguishedName = $_.DistinguishedName
                }
            }
        } -ArgumentList $currentOU, $allUsersOU -ErrorAction Stop

        # 7. ִ�з�ҳ����
        $totalGroups = $allGroups.Count
        $skipCount = ($page - 1) * $pageSize
        $pagedGroups = $allGroups | Select-Object -Skip $skipCount -First $pageSize

        # 8. ���»Ự�е������
        $session.groupCountStatus = $totalGroups
        $script:sessions[$sessionId] = $session

        # 9. ���سɹ���Ӧ
        Send-JsonResponse $response 200 @{
            success = $true
            connected = $true
            groups = $pagedGroups
            total = $totalGroups
            page = $page
            pageSize = $pageSize
            currentOU = $currentOU
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Error "[Get-GroupList ����] $errorMsg"
        
        # ���ݻỰ״̬�����ʵ�������״̬
        $isConnected = if ($session) { $session.domainContext.IsConnected } else { $false }
        
        Send-JsonResponse $response 500 @{
            success = $false
            connected = $isConnected
            message = "��ȡ���б�ʧ��: $errorMsg"
        }
    }
}




function script:Create-Group {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    # ��֤�����ֶ�
    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.groupName) -or [string]::IsNullOrEmpty($requestData.groupSam)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�����ƺ����˻�������Ϊ��" }
        return
    }

    try {
        $groupName = $requestData.groupName.Trim()
        $groupSam = $requestData.groupSam.Trim()
        $groupDesc = $requestData.groupDescription.Trim()

        $script:connectionStatus = "���ڴ����� [$groupName]..."

        # ������Ƿ��Ѵ���
        $exists = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($samAccount)
            Import-Module ActiveDirectory -ErrorAction Stop
            $group = Get-ADGroup -Filter "SamAccountName -eq '$samAccount'" -ErrorAction SilentlyContinue
            return $null -ne $group
        } -ArgumentList $groupSam -ErrorAction Stop

        if ($exists) {
            Send-JsonResponse $response 400 @{ success = $false; message = "���˻���[$groupSam]�Ѵ��ڣ������" }
            return
        }

        # Զ�̴�����
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($name, $sam, $desc, $ou)
            Import-Module ActiveDirectory -ErrorAction Stop

            $groupParams = @{
                Name            = $name
                SamAccountName  = $sam
                Description     = $desc
                GroupCategory   = "Security"
                GroupScope      = "Global"
                Path            = $ou			
            }

            New-ADGroup @groupParams -ErrorAction Stop
            return Get-ADGroup -Identity $sam -Properties Description -ErrorAction Stop
        } -ArgumentList $groupName, $groupSam, $groupDesc, $script:currentOU -ErrorAction Stop

        # ���¼������б�
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "�� [$groupName] �����ɹ�"
            groupCount = $script:groupCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "������ʧ��: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "������ʧ��: $errorMsg"
        }
    }
}

function script:Add-UserToGroup {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    # ��֤����
    if (-not $requestData -or -not $requestData.groupSam -or -not $requestData.userSams -or $requestData.userSams.Count -eq 0) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩ���˻���������һ���û��˻���" }
        return
    }

    try {
        $groupSam = $requestData.groupSam.Trim()
        $userSams = $requestData.userSams

        $script:connectionStatus = "���ڽ��û���ӵ��� [$groupSam]..."

        # Զ��ִ����Ӳ���
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($group, $users)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # ��֤���Ƿ����
            $adGroup = Get-ADGroup -Filter "SamAccountName -eq '$group'" -ErrorAction Stop
            
            foreach ($user in $users) {
                # ��֤�û��Ƿ����
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction Stop
                
                # ����û�����
                Add-ADGroupMember -Identity $adGroup -Members $adUser -ErrorAction Stop
            }
            
            return $true
        } -ArgumentList $groupSam, $userSams -ErrorAction Stop

        # ���¼����û������б��Է�ӳ����
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "�ѳɹ��� $($userSams.Count) ���û���ӵ��� [$groupSam]"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "����û�����ʧ��: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "����û�����ʧ��: $errorMsg"
        }
    }
}

function script:Filter-Groups {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $filterText = $context.Request.QueryString["filter"]

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    try {
        if ([string]::IsNullOrEmpty($filterText)) {
            $filteredGroups = $script:allGroups
        }
        else {
            $lowerFilter = $filterText.ToLower()
            $filteredGroups = @($script:allGroups | Where-Object {
                $_.Name.ToLower() -like "*$lowerFilter*" -or
                $_.SamAccountName.ToLower() -like "*$lowerFilter*" -or
                ( (-not [string]::IsNullOrEmpty($_.Description)) -and $_.Description.ToLower() -like "*$lowerFilter*" )
            })
        }

        Send-JsonResponse $response 200 @{ 
            success = $true 
            groups = $filteredGroups
            count = $filteredGroups.Count
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "ɸѡ��ʧ��: $errorMsg"
        }
    }
}
