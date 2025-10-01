<# 
ͨ�ø�������
#>

# �޸�ƴ��ת���߼���������ȷ��ת������
function Convert-ToPinyin {
    param([string]$ChineseText)
    # ����PinyinConverter.ps1�ж����ConvertToPinyin����
    if (Get-Command -Name ConvertToPinyin -ErrorAction SilentlyContinue) {
        return ConvertToPinyin -CnName $ChineseText -CaseFormat "Lower"
    }
    throw "ƴ��ת������δ�ҵ�����ȷ��PinyinConverter.ps1����ȷ����"
}

# ������֤��������ǰ���ͳһ����
function Validate-Password {
    param([string]$Password)
    $errors = @()
    if ($Password.Length -lt 8) { $errors += "���볤������8λ" }
    if (-not ($Password -cmatch '[A-Z]')) { $errors += "�������д��ĸ" }
    if (-not ($Password -cmatch '[a-z]')) { $errors += "�����Сд��ĸ" }
    if (-not ($Password -match '\d')) { $errors += "���������" }
    if (-not ($Password -match '[^a-zA-Z0-9]')) { $errors += "����������ַ�����@#$��" }
    return $errors
}

# ��ȡ�������ݺ�������·��ʹ�ã�
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
        Write-Error "��ȡ��������ʧ��: $_"
        return $null
    }
}

# JSON��Ӧ���ͺ���
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
        return "����"
    }
    return $Date.ToString("yyyy-MM-dd HH:mm:ss")
}