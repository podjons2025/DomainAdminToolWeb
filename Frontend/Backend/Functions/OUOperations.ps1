<# 
OU操作函数
#>

function Get-OUList {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    try {
        # 远程获取所有OU
        $script:allOUs = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName |
                Where-Object { $_.Name -ne "Domain Controllers" } |			
                Select-Object Name, DistinguishedName |
                Sort-Object Name
        } -ErrorAction Stop

        # 获取默认Users容器信息
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        $defaultUsersOU = "CN=Users,$domainDN"
        
        # 构建包含固定项的OU列表
        $fixedItems = @(
            [PSCustomObject]@{
                Name = "默认Users"
                DistinguishedName = $defaultUsersOU
            },
            [PSCustomObject]@{
                Name = "全部Users"
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
            message = "获取OU列表失败: $errorMsg"
        }
    }
}

function Create-OU {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.ouName)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供OU名称" }
        return
    }

    $newOUName = $requestData.ouName.Trim()

    # 验证OU名称
    if ([string]::IsNullOrWhiteSpace($newOUName)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "OU名称不能为空或仅包含空格" }
        return
    }

    # 检查非法字符
    $invalidChars = '[\\/:*?"<>|]'
    if ($newOUName -match $invalidChars) {
        $matchedChar = $matches[0]
        Send-JsonResponse $response 400 @{ 
            success = $false 
            message = "OU名称包含非法字符: `"$matchedChar`"，请删除后重试"
        }
        return
    }

    try {
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        
        # 远程创建OU
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($name, $path)
            Import-Module ActiveDirectory -ErrorAction Stop
            New-ADOrganizationalUnit -Name $name -Path $path -ProtectedFromAccidentalDeletion $false
        } -ArgumentList $newOUName, $domainDN -ErrorAction Stop

        # 重新加载OU列表
        $ous = Get-OUListInternal

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "OU创建成功"
            ous = $ous
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "创建OU失败: $errorMsg"
        }
    }
}

function Switch-OU {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.ouDn)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供OU的DistinguishedName" }
        return
    }

    try {
        $selectedOU = $requestData.ouDn
        $script:currentOU = $selectedOU

        # 检查是否选择了"全部Users"
        $domainDN = $script:domainContext.DomainInfo.DefaultPartition
        $allUsersOUDN = "CN=Users,$domainDN"
        
        if ($requestData.ouName -eq "全部Users") {
            $script:allUsersOU = $allUsersOUDN
        }
        else {
            $script:allUsersOU = $null
        }

        # 重新加载用户和组
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "已切换到OU: $selectedOU"
            currentOU = $selectedOU
            userCount = $script:userCountStatus
            groupCount = $script:groupCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "切换OU失败: $errorMsg"
        }
    }
}

# 内部函数：获取OU列表
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
        Write-Error "获取OU列表失败: $_"
        return $null
    }
}