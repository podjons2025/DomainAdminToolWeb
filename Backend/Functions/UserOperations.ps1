<# 
用户操作函数
#>

function LoadUserList {
    if (-not $script:domainContext) {
        return
    }

    try {
        $script:connectionStatus = "正在加载 OU: $($script:currentOU) 中的用户..."
        
        $script:allUsers.Clear()

        # 远程加载用户
        $remoteUsers = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($searchBase, $allUsersOU)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            if ($allUsersOU) {
                $users = Get-ADUser -Filter * -Properties DisplayName, SamAccountName, MemberOf, EmailAddress, TelephoneNumber, LockedOut, Description, Enabled, AccountExpirationDate -ErrorAction Stop
            }
            else {
                # 使用 -SearchBase 参数只查询指定OU中的用户
                $users = Get-ADUser -Filter * -SearchBase $searchBase `
                    -Properties DisplayName, SamAccountName, MemberOf, EmailAddress, TelephoneNumber, LockedOut, Description, Enabled, AccountExpirationDate `
                    -ErrorAction Stop
            }

            $users | ForEach-Object {
                $groupNames = $_.MemberOf | ForEach-Object { if ($_ -match 'CN=([^,]+)') { $matches[1] } }
                $groupsString = if ($groupNames) { $groupNames -join ', ' } else { '无' }
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
        $script:connectionStatus = "已加载 OU: $($script:currentOU) 中的 $($script:userCountStatus) 个用户"
    }
    catch {
        $script:connectionStatus = "加载用户失败: $($_.Exception.Message)"
        Write-Error $_.Exception.Message
    }
}

function Get-UserList {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    # 确保用户列表已加载
    if ($script:allUsers.Count -eq 0) {
        LoadUserList
    }

    Send-JsonResponse $response 200 @{ 
        success = $true 
        users = $script:allUsers
        count = $script:userCountStatus
    }
}

function Create-User {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    # 验证必填字段
    $requiredFields = @('cnName', 'username', 'password', 'confirmPassword')
    foreach ($field in $requiredFields) {
        if (-not $requestData.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace($requestData.$field)) {
            Send-JsonResponse $response 400 @{ success = $false; message = "请填写完整信息: $field" }
            return
        }
    }

    # 验证密码一致性
    if ($requestData.password -ne $requestData.confirmPassword) {
        Send-JsonResponse $response 400 @{ success = $false; message = "两次输入的密码不一致" }
        return
    }

    # 验证密码复杂度
    if ($requestData.password.Length -lt 8 -or 
        $requestData.password -notmatch '[A-Z]' -or 
        $requestData.password -notmatch '[a-z]' -or 
        $requestData.password -notmatch '[0-9]' -or 
        $requestData.password -notmatch '[^a-zA-Z0-9]') {
        Send-JsonResponse $response 400 @{ 
            success = $false 
            message = "密码必须至少8位，包含大小写字母、数字和特殊字符(如@#$)" 
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

        $script:connectionStatus = "正在创建用户 [$username]..."

        # 远程创建用户
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

        # 重新加载用户列表
        LoadUserList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "用户 [$username] 创建成功"
            userCount = $script:userCountStatus
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $script:connectionStatus = "创建用户失败: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "创建用户失败: $errorMsg"
        }
    }
}

function Toggle-UserEnabled {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
        return
    }

    if (-not $requestData -or [string]::IsNullOrEmpty($requestData.username) -or $requestData.newState -eq $null) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请提供用户名和操作状态" }
        return
    }

    try {
        $username = $requestData.username.Trim()
        $newState = $requestData.newState
        $action = if ($newState) { "启用" } else { "禁用" }

        $script:connectionStatus = "正在$action用户 [$username]..."

        # 远程执行启用/禁用操作
        $remoteResult = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            param($user, $state)
            Import-Module ActiveDirectory -ErrorAction Stop
            $adUser = Get-ADUser -Filter { SamAccountName -eq $user } -ErrorAction Stop
            Set-ADUser -Identity $adUser.DistinguishedName -Enabled $state -ErrorAction Stop
            $updatedUser = Get-ADUser -Identity $adUser.DistinguishedName -Properties Enabled -ErrorAction Stop
            return $updatedUser.Enabled
        } -ArgumentList $username, $newState -ErrorAction Stop

        if ($remoteResult -ne $newState) {
            throw "用户状态更新失败"
        }

        # 重新加载用户列表
        LoadUserList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "用户 [$username] $action成功"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $action = if ($requestData.newState) { "启用" } else { "禁用" }
        $script:connectionStatus = "${action}用户失败: $errorMsg"
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = "${action}用户失败: $errorMsg"
        }
    }
}

function Filter-Users {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $filterText = $context.Request.QueryString["filter"]

    if (-not $script:domainContext) {
        Send-JsonResponse $response 400 @{ success = $false; message = "请先连接到域" }
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
            message = "筛选用户失败: $errorMsg"
        }
    }
}