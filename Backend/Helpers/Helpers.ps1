<# 
通用辅助函数
#>

# 修复拼音转换逻辑：调用正确的转换函数
function Convert-ToPinyin {
    param([string]$ChineseText)
    # 依赖PinyinConverter.ps1中定义的ConvertToPinyin函数
    if (Get-Command -Name ConvertToPinyin -ErrorAction SilentlyContinue) {
        return ConvertToPinyin -CnName $ChineseText -CaseFormat "Lower"
    }
    throw "拼音转换函数未找到，请确保PinyinConverter.ps1已正确导入"
}

# 密码验证函数（供前后端统一规则）
function Validate-Password {
    param([string]$Password)
    $errors = @()
    if ($Password.Length -lt 8) { $errors += "密码长度至少8位" }
    if (-not ($Password -cmatch '[A-Z]')) { $errors += "需包含大写字母" }
    if (-not ($Password -cmatch '[a-z]')) { $errors += "需包含小写字母" }
    if (-not ($Password -match '\d')) { $errors += "需包含数字" }
    if (-not ($Password -match '[^a-zA-Z0-9]')) { $errors += "需包含特殊字符（如@#$）" }
    return $errors
}

# 读取请求数据函数（供路由使用）
function Read-RequestData {
    param([System.Net.HttpListenerContext]$context)
    try {
        $reader = New-Object System.IO.StreamReader($context.Request.InputStream)
        $data = $reader.ReadToEnd()
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

# JSON响应发送函数
function Send-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$response,
        [int]$statusCode,
        [PSObject]$data
    )
    $response.StatusCode = $statusCode
    $response.ContentType = "application/json; charset=utf-8"
    $json = $data | ConvertTo-Json -Depth 10
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
}


function Format-ADDate {
    param([DateTime]$Date)

    if ($Date -eq [DateTime]::MinValue -or $Date -eq $null) {
        return "永不"
    }
    return $Date.ToString("yyyy-MM-dd HH:mm:ss")
}