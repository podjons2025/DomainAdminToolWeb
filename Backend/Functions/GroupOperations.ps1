<# 
组操作函数
#>

# 注意：所有函数都添加了 script: 前缀，确保在脚本作用域中定义

function script:LoadGroupList {
    if (-not $script:domainContext) {
        return
    }

    try {
        $script:connectionStatus = "正在加载 OU: $($script:currentOU) 中的组..."
        
        $script:allGroups.Clear()

        # 远程加载组
        $remoteGroups = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($searchBase, $allUsersOU)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            if ($allUsersOU) {
                Get-ADGroup -Filter * `
                    -Properties Name, SamAccountName, Description `
                    | Select-Object Name, SamAccountName, Description				
            }
            else {
                # 使用 -SearchBase 参数只查询指定OU中的组
                Get-ADGroup -Filter * -SearchBase $searchBase `
                    -Properties Name, SamAccountName, Description `
                    | Select-Object Name, SamAccountName, Description
            }
        } -ArgumentList $script:currentOU, $script:allUsersOU -ErrorAction Stop

        $remoteGroups | ForEach-Object { $script:allGroups.Add($_) | Out-Null }
        
        $script:groupCountStatus = $script:allGroups.Count
        $script:connectionStatus = "已加载 OU: $($script:currentOU) 中的 $($script:groupCountStatus) 个组"
    }
    catch {
        $script:connectionStatus = "加载组失败: $($_.Exception.Message)"
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
        # 1. 获取并验证会话ID
        $cookie = $context.Request.Cookies["SessionId"]
        if (-not $cookie -or [string]::IsNullOrEmpty($cookie.Value)) {
            Send-JsonResponse $response 401 @{
                success = $false
                connected = $false
                message = "未检测到会话，请重新连接到域"
            }
            return
        }
        $sessionId = $cookie.Value

        # 2. 验证会话存在性
        if (-not $script:sessions.ContainsKey($sessionId)) {
            Send-JsonResponse $response 401 @{
                success = $false
                connected = $false
                message = "会话已过期或无效，请重新连接"
            }
            return
        }
        $session = $script:sessions[$sessionId]

        # 3. 验证域连接状态
        if (-not $session.domainContext.IsConnected -or -not $session.remoteSession) {
            Send-JsonResponse $response 400 @{
                success = $false
                connected = $false
                message = "请先连接到域"
            }
            return
        }

        # 4. 解析分页参数（兼容PS 5.1）
        $query = [System.Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)
        $page = if (-not [string]::IsNullOrEmpty($query["page"])) { [int]$query["page"] } else { 1 }
        $pageSize = if (-not [string]::IsNullOrEmpty($query["pageSize"])) { [int]$query["pageSize"] } else { 20 }

        # 验证分页参数有效性
        if ($page -lt 1) { $page = 1 }
        if ($pageSize -lt 1 -or $pageSize -gt 100) { $pageSize = 20 }

        # 5. 从会话获取必要信息
        $remoteSession = $session.remoteSession
        $currentOU = $session.currentOU
        $allUsersOU = $session.allUsersOU

        # 6. 远程查询AD组（PowerShell 5.1兼容语法）
        $allGroups = Invoke-Command -Session $remoteSession -ScriptBlock {
            param($searchBase, $searchAll)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # 根据参数决定查询范围
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

            # 处理组数据
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

        # 7. 执行分页处理
        $totalGroups = $allGroups.Count
        $skipCount = ($page - 1) * $pageSize
        $pagedGroups = $allGroups | Select-Object -Skip $skipCount -First $pageSize

        # 8. 更新会话中的组计数
        $session.groupCountStatus = $totalGroups
        $script:sessions[$sessionId] = $session

        # 9. 返回成功响应
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
        Write-Error "[Get-GroupList 错误] $errorMsg"
        
        # 根据会话状态返回适当的连接状态
        $isConnected = if ($session) { $session.domainContext.IsConnected } else { $false }
        
        Send-JsonResponse $response 500 @{
            success = $false
            connected = $isConnected
            message = "获取组列表失败: $errorMsg"
        }
    }
}




function script:Create-Group {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    # 验证必填字段
    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.groupName) -or [string]::IsNullOrEmpty($requestData.groupSam)) {
        Send-JsonResponse $response 400 @{ success = $false; message = "组名称和组账户名不能为空" }
        return
    }

    try {
        $groupName = $requestData.groupName.Trim()
        $groupSam = $requestData.groupSam.Trim()
        $groupDesc = $requestData.groupDescription.Trim()

        $script:connectionStatus = "正在创建组 [$groupName]..."

        # 检查组是否已存在
        $exists = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($samAccount)
            Import-Module ActiveDirectory -ErrorAction Stop
            $group = Get-ADGroup -Filter "SamAccountName -eq '$samAccount'" -ErrorAction SilentlyContinue
            return $null -ne $group
        } -ArgumentList $groupSam -ErrorAction Stop

        if ($exists) {
            Send-JsonResponse $response 400 @{ success = $false; message = "组账户名[$groupSam]已存在，请更换" }
            return
        }

        # 远程创建组
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

        # 重新加载组列表
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "组 [$groupName] 创建成功"
            groupCount = $script:groupCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "创建组失败: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "创建组失败: $errorMsg"
        }
    }
}

function script:Add-UserToGroup {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    # 验证参数
    if (-not $requestData -or -not $requestData.groupSam -or -not $requestData.userSams -or $requestData.userSams.Count -eq 0) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供组账户名和至少一个用户账户名" }
        return
    }

    try {
        $groupSam = $requestData.groupSam.Trim()
        $userSams = $requestData.userSams

        $script:connectionStatus = "正在将用户添加到组 [$groupSam]..."

        # 远程执行添加操作
        Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($group, $users)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # 验证组是否存在
            $adGroup = Get-ADGroup -Filter "SamAccountName -eq '$group'" -ErrorAction Stop
            
            foreach ($user in $users) {
                # 验证用户是否存在
                $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction Stop
                
                # 添加用户到组
                Add-ADGroupMember -Identity $adGroup -Members $adUser -ErrorAction Stop
            }
            
            return $true
        } -ArgumentList $groupSam, $userSams -ErrorAction Stop

        # 重新加载用户和组列表以反映更改
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "已成功将 $($userSams.Count) 个用户添加到组 [$groupSam]"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "添加用户到组失败: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "添加用户到组失败: $errorMsg"
        }
    }
}

function script:Filter-Groups {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $filterText = $context.Request.QueryString["filter"]

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
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
            message = "筛选组失败: $errorMsg"
        }
    }
}
