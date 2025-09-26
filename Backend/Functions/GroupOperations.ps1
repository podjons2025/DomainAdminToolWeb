<# 
��������� - �޸���
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
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    # ȷ�����б��Ѽ���
    if ($script:allGroups.Count -eq 0) {
        LoadGroupList
    }

    Send-JsonResponse $response 200 @{ 
        success = $true 
        groups = $script:allGroups
        count = $script:groupCountStatus
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
