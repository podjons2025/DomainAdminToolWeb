<# 
注意：请不要随意修改此文件，可能导致功能异常
#>

function Register-Routes {
    # 初始化路由集合
    $script:routes.Clear()

    # 1. 加载功能模块并验证正确性
    $functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "../Functions"
    $helpersDir = Join-Path -Path $PSScriptRoot -ChildPath "../Helpers"

    # ==============================================
    # 关键修改点：强制加载并合并到script作用域
    # 使用 $script:null = . 语法，确保加载到script作用域生效
    # ==============================================
    try {
        # 加载业务模块（强制到script作用域）
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "DomainOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "UserOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "GroupOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "OUOperations.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "Helpers.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "PinyinConverter.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "importExportUsers.ps1")

        Write-Host "[路由] 业务模块加载成功，目录：$functionsDir"
    }
    catch {
        Write-Error "[路由] 业务模块加载失败，文件缺失或语法错误：$_"
        return
    }

    # ==============================================
    # 验证关键功能函数是否已正确加载到script作用域
    # ==============================================
    $requiredFunctions = @(
        "Connect-ToDomain", "Disconnect-FromDomain", "Get-ConnectionStatus",
        "Get-OUList", "Create-OU", "Switch-OU",
        "Get-UserList", "Create-User", "Toggle-UserEnabled", "Filter-Users",
        "Get-GroupList", "Create-Group", "Add-UserToGroup", "Filter-Groups",
		"Read-RequestData" 
    )

    $missingFunctions = @()
    foreach ($func in $requiredFunctions) {
        # 验证函数是否存在于script作用域
        if (-not (Get-Command -Name $func -CommandType Function -Scope Script -ErrorAction SilentlyContinue)) {
            $missingFunctions += $func
        }
    }

    if ($missingFunctions.Count -gt 0) {
        Write-Error "[路由] script作用域缺失以下函数：$($missingFunctions -join ', ')"
        Write-Error "可能原因：1. 对应.ps1文件未正确加载 2. 函数存在语法错误 3. 未加载到script作用域"
        return
    }
    else {
        Write-Host "[路由] script作用域验证通过，共14个必要函数"
    }

    # 3. 注册路由，核心逻辑：将请求映射到对应的script作用域函数
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