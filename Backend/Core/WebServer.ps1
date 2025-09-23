<# 
PowerShell������Web���������ģ�����PS 5.1�����׽������δʶ�����⣩
����HttpListenerʵ�֣����������ű��飬ֱ����ʽ·��
#>

Add-Type -AssemblyName System.Web

# ȫ�ֱ���
$script:httpListener = New-Object System.Net.HttpListener
$script:frontendPath = $null

# ==============================================
# ���ؼ��޸�1����ǰ��������ҵ��ģ�飨����script�����򣩡�
# ֱ����WebServer���㵼�룬ȷ�����к�����script���������
# ==============================================
function Import-BusinessModules {
    [CmdletBinding()]
    param()

    $functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "../Functions"
    $helpersDir = Join-Path -Path $PSScriptRoot -ChildPath "../Helpers"

    # ��֤Ŀ¼����
    if (-not (Test-Path $functionsDir -PathType Container)) {
        throw "FunctionsĿ¼������: $functionsDir"
    }
    if (-not (Test-Path $helpersDir -PathType Container)) {
        throw "HelpersĿ¼������: $helpersDir"
    }

    # �������ģ�飨��ʽscript������
    try {
        Write-Host "[ģ��] ��ʼ����ҵ��ģ��..."
        # ���빦��ģ�飨ǿ��script������
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "DomainOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "UserOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "GroupOperations.ps1")
        $script:null = . (Join-Path -Path $functionsDir -ChildPath "OUOperations.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "Helpers.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "PinyinConverter.ps1")
        $script:null = . (Join-Path -Path $helpersDir -ChildPath "importExportUsers.ps1")

        Write-Host "[·��] ҵ��ģ�鵼��ɹ���Ŀ¼��$functionsDir��"

        # ��֤���ĺ����Ƿ���ڣ�����ͨ��������������޷�������
        $requiredFuncs = @(
            "Get-ConnectionStatus", "Connect-ToDomain", "Disconnect-FromDomain",
            "Get-OUList", "Create-OU", "Switch-OU",
            "Get-UserList", "Create-User", "Toggle-UserEnabled", "Filter-Users",
            "Get-GroupList", "Create-Group", "Add-UserToGroup", "Filter-Groups",
            "Read-RequestData"  
        )

        $missingFuncs = @()
        foreach ($func in $requiredFuncs) {
            if (-not (Get-Command -Name $func -CommandType Function -Scope Script -ErrorAction SilentlyContinue)) {
                $missingFuncs += $func
            }
        }

        if ($missingFuncs.Count -gt 0) {
            throw "���º��ĺ���ȱʧ������Ӧ.ps1�ļ���: $($missingFuncs -join ', ')"
        }

        Write-Host "[ģ��] 14������ҵ����ȫ������ɹ���script������"
    }
    catch {
        Write-Error "[ģ��] ����ʧ��: $_"
        throw  # ��ֹ����������
    }
}

# ==============================================
# ��Ǩ�ƣ���Router.ps1����Read-RequestData���˴���
# ��������Router.ps1��ֱ����WebServer�ж���
# ==============================================
function script:Read-RequestData {
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

# ==============================================
# ǰ��Ŀ¼������������
# ==============================================
function Resolve-FrontendPath {
    [CmdletBinding()]
    param()
    
    $rawPath = Join-Path -Path $PSScriptRoot -ChildPath "../../Frontend"
    try {
        $resolvedPath = Convert-Path -Path $rawPath -ErrorAction Stop
        Write-Host "[��Ϣ] ǰ��Ŀ¼�����ɹ�: $resolvedPath"
        return $resolvedPath
    }
    catch {
        Write-Warning "[����] ǰ��Ŀ¼ת��ʧ�ܣ�ʹ��ԭʼ·��: $rawPath"
        return $rawPath
    }
}

# ==============================================
# URLȨ�����ã�������
# ==============================================
function Configure-UrlAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$prefix
    )
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "���Թ���Ա������У������޷�����URL�˿�Ȩ��"
    }
    
    try {
        $netshOutput = netsh http add urlacl url=$prefix user=Administrators 2>&1
        if ($LASTEXITCODE -ne 0 -and $netshOutput -notmatch "�Ѵ���") {
            Write-Warning "[����] URLȨ��ע�᲻��ȫ����������������: $netshOutput"
        }
        else {
            Write-Host "[��Ϣ] URLȨ�����óɹ�: $prefix"
        }
    }
    catch {
        Write-Warning "[����] URLȨ������ʧ�ܣ����ܲ�Ӱ�챾�ز��ԣ�: $_"
    }
}

# ==============================================
# �������������������Ƴ�Router.ps1������
# ==============================================
function Start-WebServer {
    [CmdletBinding()]
    param(
        [string]$prefix = "http://localhost:8080/"
    )

    # 1. ����ҵ��ģ�飨�����һ����
    try {
        Import-BusinessModules
    }
    catch {
        Write-Error "[����] ģ�鵼��ʧ�ܣ��������޷�����: $_"
        return
    }

    # 2. ����ǰ��Ŀ¼
    $script:frontendPath = Resolve-FrontendPath
    if (-not (Test-Path -Path $script:frontendPath -PathType Container)) {
        Write-Error "[��������] ǰ��Ŀ¼������: $script:frontendPath"
        return
    }

    # 3. ����URLȨ��
    try {
        Configure-UrlAcl -prefix $prefix
    }
    catch {
        Write-Error "[��������] Ȩ������ʧ��: $_"
        return
    }

    # 4. ����������
    if (-not $script:httpListener.IsListening) {
        $script:httpListener.Prefixes.Clear()
        $script:httpListener.Prefixes.Add($prefix)

        try {
            $script:httpListener.Start()
            Write-Host "`n====================================="
            Write-Host "Web��������������PowerShell 5.1���ݣ�"
            Write-Host "���ʵ�ַ: $prefix"
            Write-Host "ǰ��Ŀ¼: $script:frontendPath"
            Write-Host "��Ctrl+Cֹͣ������"
            Write-Host "=====================================`n"

            # 5. �������󣨺��ģ�ֱ����ʽ�ж�·�ɣ�
            while ($script:httpListener.IsListening) {
                try {
                    $context = $script:httpListener.GetContext()
                    Handle-Request -context $context
                }
                catch [System.Net.HttpListenerException] {
                    if ($_.Exception.Message -notmatch "������ȡ��") {
                        Write-Error "[�����쳣] HttpListener����: $($_.Exception.Message)"
                    }
                }
                catch {
                    Write-Error "[�����쳣] δ֪����: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Error "[��������] ����������ʧ�ܣ��˿ڿ��ܱ�ռ�ã�: $($_.Exception.Message)"
            Write-Host "`n�Ų齨�飺"
            Write-Host "1. ���˿�ռ�ã�netstat -ano | findstr :$([Uri]$prefix | Select-Object -ExpandProperty Port)"
            Write-Host "2. ����ռ�ý��̣�taskkill /F /PID ��ռ�ý���ID��"
            Write-Host "3. �����˿�������Start-WebServer -Prefix http://localhost:8081/"
        }
    }
}

# ==============================================
# ֹͣ��������������
# ==============================================
function Stop-WebServer {
    if ($script:httpListener.IsListening) {
        $script:httpListener.Stop()
        $script:httpListener.Close()
        Write-Host "`n[��Ϣ] Web��������ֹͣ"
    }
}

# ==============================================
# �������޸�2����ʽ·���жϣ����׽�����������⣩��
# ������·�ɹ�ϣ��ֱ��if-else�жϷ���+·��
# ==============================================
# �滻ԭ�ļ���Handle-Request�����ڵ�·�ɴ����֣���Լ��251-286�У�
function Handle-Request {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerContext]$context
    )

    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.LocalPath
    $method = $request.HttpMethod

    Write-Host "[����] $method $path"

    try {
        # ==========================================
        # ·��ƥ�䣨��ȷ����script�������еĺ�����
        # ==========================================
        # �������·��
        if ($method -eq "GET" -and $path -eq "/api/connection-status") {
            & $script:Get-ConnectionStatus $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/connect") {
            & $script:Connect-ToDomain $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/disconnect") {
            & $script:Disconnect-FromDomain $context
        }
        # OU����·��
        elseif ($method -eq "GET" -and $path -eq "/api/ous") {
            & $script:Get-OUList $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/ous") {
            & $script:Create-OU $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/switch-ou") {
            & $script:Switch-OU $context
        }
        # �û�����·��
        elseif ($method -eq "GET" -and $path -eq "/api/users") {
            & $script:Get-UserList $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/users") {
            & $script:Create-User $context
        }
        elseif ($method -eq "PUT" -and $path -eq "/api/users/enable") {
            & $script:Toggle-UserEnabled $context
        }
        elseif ($method -eq "GET" -and $path -like "/api/users/filter*") {
            & $script:Filter-Users $context
        }
        # �����·��
        elseif ($method -eq "GET" -and $path -eq "/api/groups") {
            & $script:Get-GroupList $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/groups") {
            & $script:Create-Group $context
        }
        elseif ($method -eq "POST" -and $path -eq "/api/groups/add-user") {
            & $script:Add-UserToGroup $context
        }
        elseif ($method -eq "GET" -and $path -like "/api/groups/filter*") {
            & $script:Filter-Groups $context
        }
        # ��̬�ļ�����
        elseif ($method -eq "GET") {
            Serve-StaticFile -context $context
        }
        else {
            Send-Response -response $response -statusCode 404 -content "δ�ҵ��������Դ"
        }
    }
    catch {
        Write-Error "[�������] $($_.Exception.Message)"
        Send-Response -response $response -statusCode 500 -content "�������ڲ�����: $($_.Exception.Message)"
    }
    finally {
		$response.OutputStream.Flush()
        $response.Close()
    }
}





# ==============================================
# ���º����������䣨��ȷ��Send-JsonResponse��script������
# ==============================================
function Serve-StaticFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerContext]$context
    )

    $request = $context.Request
    $response = $context.Response
    $path = $request.Url.LocalPath

    $filePath = if ($path -eq "/" -or [string]::IsNullOrEmpty($path)) {
        Join-Path -Path $script:frontendPath -ChildPath "index.html"
    }
    else {
        Join-Path -Path $script:frontendPath -ChildPath $path.TrimStart('/')
    }

    if (Test-Path $filePath -PathType Leaf) {
        try {
            $content = Get-Content $filePath -Raw -Encoding UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)

            $response.ContentLength64 = $bytes.Length
            $response.ContentType = Get-ContentType -filePath $filePath
            $response.OutputStream.Write($bytes, 0, $bytes.Length)

            Write-Host "[��Ӧ] 200 OK: $filePath"
        }
        catch {
            Send-Response -response $response -statusCode 500 -content "�޷���ȡ�ļ�: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "[��Ӧ] 404 δ�ҵ�: $filePath"
        Send-Response -response $response -statusCode 404 -content "�ļ�δ�ҵ�: $path"
    }
}

function Get-ContentType {
    [CmdletBinding()]
    param([string]$filePath)
    
    $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
    switch ($ext) {
        ".html" { return "text/html; charset=utf-8" }
        ".css" { return "text/css; charset=utf-8" }
        ".js" { return "application/javascript; charset=utf-8" }
        ".json" { return "application/json; charset=utf-8" }
        ".png" { return "image/png" }
        ".jpg" { return "image/jpeg" }
        ".gif" { return "image/gif" }
        default { return "application/octet-stream" }
    }
}

function Send-Response {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerResponse]$response,
        [int]$statusCode = 200,
        [string]$content = "",
        [string]$contentType = "text/plain; charset=utf-8"
    )

    $response.StatusCode = $statusCode
    $response.ContentType = $contentType
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $response.ContentLength64 = $bytes.Length

    try {
        $response.OutputStream.Write($bytes, 0, $bytes.Length)
        $response.OutputStream.Flush()
    }
    catch {
        Write-Warning "[��Ӧ����] д��ʧ��: $($_.Exception.Message)"
    }
}

# ���ؼ��޸�3��Send-JsonResponseǿ��script������
function script:Send-JsonResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Net.HttpListenerResponse]$response,
        [int]$statusCode = 200,
        [PSObject]$data
    )

    $json = $data | ConvertTo-Json -Depth 10 -ErrorAction Stop
    Send-Response -response $response -statusCode $statusCode -content $json -contentType "application/json; charset=utf-8"
}

# ��ֹ����������
$exitHandler = {
    Stop-WebServer
    exit 0
}
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $exitHandler | Out-Null