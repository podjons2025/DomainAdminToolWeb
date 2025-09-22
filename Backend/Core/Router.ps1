<# 
路由注册与管理（修复函数作用域问题）
#>

function Register-Routes {
    # 清除现有路由
    $script:routes.Clear()

    # 1. 定义绝对路径（已验证正确，保留）
    $functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "../Functions"
    $helpersDir = Join-Path -Path $PSScriptRoot -ChildPath "../Helpers"

    # ==============================================
    # 核心修复：强制函数进入script作用域
    # 用 $script:null = . 加载模块，让函数定义在script作用域生效
    # ==============================================
    try {
        # 导入功能模块（强制script作用域）
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "DomainOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "UserOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "GroupOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "OUOperations.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "Helpers.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "PinyinConverter.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "importExportUsers.ps1")

        Write-Host "[路由] 业务模块导入成功（目录：$functionsDir）"
    }
    catch {
        Write-Error "[路由] 业务模块导入失败！文件缺失或语法错误：$_"
        return
    }

    # ==============================================
    # 关键验证：在script作用域检查函数是否存在
    # ==============================================
    $requiredFunctions = @(
        "Connect-ToDomain", "Disconnect-FromDomain", "Get-ConnectionStatus",
        "Get-OUList", "Create-OU", "Switch-OU",
        "Get-UserList", "Create-User", "Toggle-UserEnabled", "Filter-Users",
        "Get-GroupList", "Create-Group", "Add-UserToGroup", "Filter-Groups"
    )

    $missingFunctions = @()
    foreach ($func in $requiredFunctions) {
        # 明确在script作用域查找函数
        if (-not (Get-Command -Name $func -CommandType Function -Scope Script -ErrorAction SilentlyContinue)) {
            $missingFunctions += $func
        }
    }

    if ($missingFunctions.Count -gt 0) {
        Write-Error "[路由] script作用域缺失函数：$($missingFunctions -join ', ')"
        Write-Error "原因：1. 对应.ps1文件中未定义该函数；2. 函数定义有语法错误；3. 导入未进入script作用域"
        return
    }
    else {
        Write-Host "[路由] script作用域验证通过，14个核心函数均存在"
    }

    # 3. 注册路由（保留原有绑定，此时函数在script作用域可见）
    $script:routes["POST|/api/connect"] = { param($ctx) Get-ConnectionStatus $ctx }
    $script:routes["POST|/api/disconnect"] = { param($ctx) Disconnect-FromDomain $ctx }
    $script:routes["GET|/api/connection-status"] = { param($ctx) Get-ConnectionStatus $ctx }

    $script:routes["GET|/api/ous"] = { param($ctx) Get-OUList $ctx }
    $script:routes["POST|/api/ous"] = { param($ctx) Create-OU $ctx }
    $script:routes["POST|/api/switch-ou"] = { param($ctx) Switch-OU $ctx }

    $script:routes["GET|/api/users"] = { param($ctx) Get-UserList $ctx }
    $script:routes["POST|/api/users"] = { param($ctx) Create-User $ctx }
    $script:routes["PUT|/api/users/enable"] = { param($ctx) Toggle-UserEnabled $ctx }
    $script:routes["GET|/api/users/filter"] = { param($ctx) Filter-Users $ctx }

    $script:routes["GET|/api/groups"] = { param($ctx) Get-GroupList $ctx }
    $script:routes["POST|/api/groups"] = { param($ctx) Create-Group $ctx }
    $script:routes["POST|/api/groups/add-user"] = { param($ctx) Add-UserToGroup $ctx }
    $script:routes["GET|/api/groups/filter"] = { param($ctx) Filter-Groups $ctx }

    Write-Host "[路由] 已注册 $($script:routes.Count) 条路由"
}

function Read-RequestData {
    param([System.Net.HttpListenerContext]$context)

    try {
        $reader = New-Object System.IO.StreamReader($context.Request.InputStream)
        $data = $reader.ReadToEnd()
        $reader.Dispose()
        
        if (-not [string]::IsNullOrEmpty($data)) {
            return $data | ConvertFrom-Json
        }
        return $null
    }
    catch {
        Write-Error "读取请求数据失败: $_"
        return $null
    }
}