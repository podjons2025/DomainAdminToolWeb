<# 
ע�⣺�벻Ҫ�����޸Ĵ��ļ������ܵ��¹����쳣
#>

function Register-Routes {
    # ��ʼ��·�ɼ���
    $script:routes.Clear()

    # 1. ���ع���ģ�鲢��֤��ȷ��
    $functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "../Functions"
    $helpersDir = Join-Path -Path $PSScriptRoot -ChildPath "../Helpers"

    # ==============================================
    # �ؼ��޸ĵ㣺ǿ�Ƽ��ز��ϲ���script������
    # ʹ�� $script:null = . �﷨��ȷ�����ص�script��������Ч
    # ==============================================
    try {
        # ����ҵ��ģ�飨ǿ�Ƶ�script������
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "DomainOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "UserOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "GroupOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "OUOperations.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "Helpers.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "PinyinConverter.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "importExportUsers.ps1")

        Write-Host "[·��] ҵ��ģ����سɹ���Ŀ¼��$functionsDir"
    }
    catch {
        Write-Error "[·��] ҵ��ģ�����ʧ�ܣ��ļ�ȱʧ���﷨����$_"
        return
    }

    # ==============================================
    # ��֤�ؼ����ܺ����Ƿ�����ȷ���ص�script������
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
        # ��֤�����Ƿ������script������
        if (-not (Get-Command -Name $func -CommandType Function -Scope Script -ErrorAction SilentlyContinue)) {
            $missingFunctions += $func
        }
    }

    if ($missingFunctions.Count -gt 0) {
        Write-Error "[·��] script������ȱʧ���º�����$($missingFunctions -join ', ')"
        Write-Error "����ԭ��1. ��Ӧ.ps1�ļ�δ��ȷ���� 2. ���������﷨���� 3. δ���ص�script������"
        return
    }
    else {
        Write-Host "[·��] script��������֤ͨ������14����Ҫ����"
    }

    # 3. ע��·�ɣ������߼���������ӳ�䵽��Ӧ��script��������
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

    Write-Host "[·��] ��ע�� $($script:routes.Count) ��·��"
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
        Write-Error "��ȡ��������ʧ��: $_"
        return $null
    }
}