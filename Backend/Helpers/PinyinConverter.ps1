<# 
����תƴ�����ߣ�����NPinyin.dll��
֧���Զ������Ϻ������еĶ�����
#>

function ConvertToPinyin {
    param(
        [string]$CnName,
        [string]$Prefix,
        [ValidateSet("Lower", "Upper", "TitleCase")]
        [string]$CaseFormat = "Lower",
        [string]$ConfigFilePath = "$PSScriptRoot\pinyin_config.txt"
    )

    # ��GUI�ؼ���ȡ���루Ĭ���߼���
    if (-not $CnName) {
        $CnName = $script:textCnName.Text.Trim()
    }
    if (-not $Prefix) {
        $Prefix = $script:textPrefix.Text.Trim()
    }

    if (-not $CnName) {
        if ($script:textPinyin) { $script:textPinyin.Text = "" }
        return ""
    }

    try {
        # ���������ļ�
        if (-not (Test-Path $ConfigFilePath)) {
            throw "δ�ҵ������ļ� $($ConfigFilePath)����ȷ�ϸ��ļ�����"
        }

        # ���������ļ�
        $configContent = Get-Content $ConfigFilePath -Raw
        $specialSurnames = @{}
        $specialGivenNames = @{}
        $doubleSurnames = @()
        
        $currentSection = $null
        
        foreach ($line in $configContent -split "`n") {
            $line = $line.Trim()
            # �������к�ע��
            if ([string]::IsNullOrEmpty($line) -or $line.StartsWith("#")) {
                continue
            }
            
            # ���section���
            if ($line.StartsWith("[") -and $line.EndsWith("]")) {
                $currentSection = $line.Trim("[]").ToLower()
                continue
            }
            
            # ���ݵ�ǰsection��������
            switch ($currentSection) {
                "specialsurnames" {
                    $parts = $line -split "=", 2
                    if ($parts.Count -eq 2) {
                        $char = $parts[0].Trim()
                        $pinyin = $parts[1].Trim()
                        $specialSurnames[$char] = $pinyin
                    }
                }
                "specialgivennames" {
                    $parts = $line -split "=", 2
                    if ($parts.Count -eq 2) {
                        $char = $parts[0].Trim()
                        $pinyin = $parts[1].Trim()
                        $specialGivenNames[$char] = $pinyin
                    }
                }
                "doublesurnames" {
                    $doubleSurnames += $line
                }
            }
			$doubleSurnames = $doubleSurnames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        }

        # ����NPinyin.dll
        $dllPath = "$PSScriptRoot\NPinyin.dll"
        if (-not (Test-Path $dllPath)) {
            throw "δ�ҵ�NPinyin.dll����ȷ�ϸ��ļ������ڽű�Ŀ¼"
        }
        
        # ���Լ���DLL
        if (-not ([System.Management.Automation.PSTypeName]"NPinyin.Pinyin").Type) {
            Add-Type -Path $dllPath | Out-Null
        }
        
        $surnamePinyin = ""
        $remainingName = $CnName
        $surnameProcessed = $false
        
        # �ȼ�鸴��
        foreach ($surname in $doubleSurnames) {
            if ($CnName.StartsWith($surname)) {
                $surnamePinyin = [NPinyin.Pinyin]::GetPinyin($surname).Replace(" ", "")
                $remainingName = $CnName.Substring($surname.Length)
                $surnameProcessed = $true
                break
            }
        }
        
        # ������Ǹ��գ���鵥����������
        if (-not $surnameProcessed) {
            $firstChar = $CnName.Substring(0, 1)
            if ($specialSurnames.ContainsKey($firstChar)) {
                $surnamePinyin = $specialSurnames[$firstChar]
                $remainingName = $CnName.Substring(1)
                $surnameProcessed = $true
            }
        }
        
        # ��������������ϣ�ʹ��Ĭ��ת��
        if (-not $surnameProcessed) {
            $firstChar = $CnName.Substring(0, 1)
            $surnamePinyin = [NPinyin.Pinyin]::GetPinyin($firstChar).Replace(" ", "")
            $remainingName = $CnName.Substring(1)
        }
        
        # ת�����ֲ��֣����������
        $givenNamePinyin = ""
        foreach ($char in $remainingName.ToCharArray()) {
            $charStr = $char.ToString()
            # ����Ƿ����Զ���ƴ��
            if ($specialGivenNames.ContainsKey($charStr)) {
                $givenNamePinyin += $specialGivenNames[$charStr]
            }
            else {
                # ʹ��Ĭ��ת��
                $givenNamePinyin += [NPinyin.Pinyin]::GetPinyin($charStr).Replace(" ", "")
            }
        }
        
        # ������Ϻ�����
        $outputPinyin = $surnamePinyin + $givenNamePinyin

        # Ӧ�ô�Сд��ʽ
        switch ($CaseFormat) {
            "Lower"    { $outputPinyin = $outputPinyin.ToLower() }
            "Upper"    { $outputPinyin = $outputPinyin.ToUpper() }
            "TitleCase" { 
                $outputPinyin = (Get-Culture).TextInfo.ToTitleCase($outputPinyin.ToLower())
            }
        }

        # ���ǰ׺
        $username = if ([string]::IsNullOrEmpty($Prefix)) { $outputPinyin } else { "$Prefix$outputPinyin" }

        # ����GUI�����
        if ($script:textPinyin) { $script:textPinyin.Text = $username }
        
        return $username
    }
    catch {
        $errorMsg = "ƴ��ת��ʧ��: $_"
        if ($script:textPinyin) { $script:textPinyin.Text = $errorMsg }
        return $errorMsg
    }
}
