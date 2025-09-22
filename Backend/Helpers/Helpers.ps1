<# 
ͨ�ø�������
#>

function Convert-ToPinyin {
    param([string]$ChineseText)

    # �����ʵ�֣�ʵ����Ŀ�п���ʹ�ø����Ƶ�ƴ��ת����
    # ʵ��Ӧ���н���ʹ�ó����ƴ��ת��ģ��
    Add-Type -AssemblyName System.Web
    return [System.Web.HttpUtility]::UrlEncode($ChineseText)
}

function Validate-Password {
    param([string]$Password)

    # ������֤�߼�
    if ($Password.Length -lt 8) {
        return $false, "���볤�ȱ�������8λ"
    }
    if ($Password -notmatch '[A-Z]') {
        return $false, "������������д��ĸ"
    }
    if ($Password -notmatch '[a-z]') {
        return $false, "����������Сд��ĸ"
    }
    if ($Password -notmatch '[0-9]') {
        return $false, "��������������"
    }
    if ($Password -notmatch '[^a-zA-Z0-9]') {
        return $false, "���������������ַ�(��@#$)"
    }
    return $true, "������֤ͨ��"
}

function Format-ADDate {
    param([DateTime]$Date)

    if ($Date -eq [DateTime]::MinValue -or $Date -eq $null) {
        return "����"
    }
    return $Date.ToString("yyyy-MM-dd HH:mm:ss")
}