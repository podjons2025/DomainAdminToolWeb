<# 
OU��������
#>

function Get-OUList {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    try {
        # Զ�̻�ȡ����OU
        $script:allOUs = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName |
                Where-Object { $_.Name -ne "Domain Controllers" } |			
                Select-Object Name, DistinguishedName |
                Sort-Object Name
        } -ErrorAction Stop

        # ��ȡĬ��Users������Ϣ
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        $defaultUsersOU = "CN=Users,$domainDN"
        
        # ���������̶����OU�б�
        $fixedItems = @(
            [PSCustomObject]@{
                Name = "Ĭ��Users"
                DistinguishedName = $defaultUsersOU
            },
            [PSCustomObject]@{
                Name = "ȫ��Users"
                DistinguishedName = $defaultUsersOU
            }
        )

        $result = $fixedItems + $script:allOUs

        Send-JsonResponse $response 200 @{ 
            success = $true 
            ous = $result
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "��ȡOU�б�ʧ��: $errorMsg"
        }
    }
}

function Create-OU {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.ouName)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩOU����" }
        return
    }

    $newOUName = $requestData.ouName.Trim()

    # ��֤OU����
    if ([string]::IsNullOrWhiteSpace($newOUName)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "OU���Ʋ���Ϊ�ջ�������ո�" }
        return
    }

    # ���Ƿ��ַ�
    $invalidChars = '[\\/:*?"<>|]'
    if ($newOUName -match $invalidChars) {
        $matchedChar = $matches[0]
        Send-JsonResponse $response 400 @{ 
            success = $false 
            message = "OU���ư����Ƿ��ַ�: `"$matchedChar`"����ɾ��������"
        }
        return
    }

    try {
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        
        # Զ�̴���OU
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($name, $path)
            Import-Module ActiveDirectory -ErrorAction Stop
            New-ADOrganizationalUnit -Name $name -Path $path -ProtectedFromAccidentalDeletion $false
        } -ArgumentList $newOUName, $domainDN -ErrorAction Stop

        # ���¼���OU�б�
        $ous = Get-OUListInternal

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "OU�����ɹ�"
            ous = $ous
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "����OUʧ��: $errorMsg"
        }
    }
}

function Switch-OU {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "�������ӵ���" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.ouDn)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩOU��DistinguishedName" }
        return
    }

    try {
        $selectedOU = $requestData.ouDn
        $script:currentOU = $selectedOU

        # ����Ƿ�ѡ����"ȫ��Users"
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        $allUsersOUDN = "CN=Users,$domainDN"
        
        if ($requestData.ouName -eq "ȫ��Users") {
            $script:allUsersOU = $allUsersOUDN
        }
        else {
            $script:allUsersOU = $null
        }

        # ���¼����û�����
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "���л���OU: $selectedOU"
            currentOU = $selectedOU
            userCount = $script:userCountStatus
            groupCount = $script:groupCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "�л�OUʧ��: $errorMsg"
        }
    }
}

# �ڲ���������ȡOU�б�
function Get-OUListInternal {
    if (-not $script:domainContext) {
        return $null
    }

    try {
        return Invoke-Command -Session $script:remoteSession -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName |
                Where-Object { $_.Name -ne "Domain Controllers" } |			
                Select-Object Name, DistinguishedName |
                Sort-Object Name
        } -ErrorAction Stop
    }
    catch {
        Write-Error "��ȡOU�б�ʧ��: $_"
        return $null
    }
}