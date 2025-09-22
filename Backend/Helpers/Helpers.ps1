<# 
通用辅助函数
#>

function Convert-ToPinyin {
    param([string]$ChineseText)

    # 这里简化实现，实际项目中可以使用更完善的拼音转换库
    # 实际应用中建议使用成熟的拼音转换模块
    Add-Type -AssemblyName System.Web
    return [System.Web.HttpUtility]::UrlEncode($ChineseText)
}

function Validate-Password {
    param([string]$Password)

    # 密码验证逻辑
    if ($Password.Length -lt 8) {
        return $false, "密码长度必须至少8位"
    }
    if ($Password -notmatch '[A-Z]') {
        return $false, "密码必须包含大写字母"
    }
    if ($Password -notmatch '[a-z]') {
        return $false, "密码必须包含小写字母"
    }
    if ($Password -notmatch '[0-9]') {
        return $false, "密码必须包含数字"
    }
    if ($Password -notmatch '[^a-zA-Z0-9]') {
        return $false, "密码必须包含特殊字符(如@#$)"
    }
    return $true, "密码验证通过"
}

function Format-ADDate {
    param([DateTime]$Date)

    if ($Date -eq [DateTime]::MinValue -or $Date -eq $null) {
        return "永不"
    }
    return $Date.ToString("yyyy-MM-dd HH:mm:ss")
}