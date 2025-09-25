<# 
中文转拼音工具（依赖NPinyin.dll）
支持自定义姓氏和名字中的多音字
#>

function ConvertToPinyin {
    param(
        [string]$CnName,
        [string]$Prefix,
        [ValidateSet("Lower", "Upper", "TitleCase")]
        [string]$CaseFormat = "Lower",
        [string]$ConfigFilePath = "$PSScriptRoot\pinyin_config.txt"
    )

    # 从GUI控件获取输入（默认逻辑）
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
        # 加载配置文件
        if (-not (Test-Path $ConfigFilePath)) {
            throw "未找到配置文件 $($ConfigFilePath)！请确认该文件存在"
        }

        # 解析配置文件
        $configContent = Get-Content $ConfigFilePath -Raw
        $specialSurnames = @{}
        $specialGivenNames = @{}
        $doubleSurnames = @()
        
        $currentSection = $null
        
        foreach ($line in $configContent -split "`n") {
            $line = $line.Trim()
            # 跳过空行和注释
            if ([string]::IsNullOrEmpty($line) -or $line.StartsWith("#")) {
                continue
            }
            
            # 检查section标记
            if ($line.StartsWith("[") -and $line.EndsWith("]")) {
                $currentSection = $line.Trim("[]").ToLower()
                continue
            }
            
            # 根据当前section处理内容
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

        # 加载NPinyin.dll
        $dllPath = "$PSScriptRoot\NPinyin.dll"
        if (-not (Test-Path $dllPath)) {
            throw "未找到NPinyin.dll！请确认该文件存在于脚本目录"
        }
        
        # 尝试加载DLL
        if (-not ([System.Management.Automation.PSTypeName]"NPinyin.Pinyin").Type) {
            Add-Type -Path $dllPath | Out-Null
        }
        
        $surnamePinyin = ""
        $remainingName = $CnName
        $surnameProcessed = $false
        
        # 先检查复姓
        foreach ($surname in $doubleSurnames) {
            if ($CnName.StartsWith($surname)) {
                $surnamePinyin = [NPinyin.Pinyin]::GetPinyin($surname).Replace(" ", "")
                $remainingName = $CnName.Substring($surname.Length)
                $surnameProcessed = $true
                break
            }
        }
        
        # 如果不是复姓，检查单字特殊姓氏
        if (-not $surnameProcessed) {
            $firstChar = $CnName.Substring(0, 1)
            if ($specialSurnames.ContainsKey($firstChar)) {
                $surnamePinyin = $specialSurnames[$firstChar]
                $remainingName = $CnName.Substring(1)
                $surnameProcessed = $true
            }
        }
        
        # 如果不是特殊姓氏，使用默认转换
        if (-not $surnameProcessed) {
            $firstChar = $CnName.Substring(0, 1)
            $surnamePinyin = [NPinyin.Pinyin]::GetPinyin($firstChar).Replace(" ", "")
            $remainingName = $CnName.Substring(1)
        }
        
        # 转换名字部分，处理多音字
        $givenNamePinyin = ""
        foreach ($char in $remainingName.ToCharArray()) {
            $charStr = $char.ToString()
            # 检查是否有自定义拼音
            if ($specialGivenNames.ContainsKey($charStr)) {
                $givenNamePinyin += $specialGivenNames[$charStr]
            }
            else {
                # 使用默认转换
                $givenNamePinyin += [NPinyin.Pinyin]::GetPinyin($charStr).Replace(" ", "")
            }
        }
        
        # 组合姓氏和名字
        $outputPinyin = $surnamePinyin + $givenNamePinyin

        # 应用大小写格式
        switch ($CaseFormat) {
            "Lower"    { $outputPinyin = $outputPinyin.ToLower() }
            "Upper"    { $outputPinyin = $outputPinyin.ToUpper() }
            "TitleCase" { 
                $outputPinyin = (Get-Culture).TextInfo.ToTitleCase($outputPinyin.ToLower())
            }
        }

        # 添加前缀
        $username = if ([string]::IsNullOrEmpty($Prefix)) { $outputPinyin } else { "$Prefix$outputPinyin" }

        # 更新GUI输入框
        if ($script:textPinyin) { $script:textPinyin.Text = $username }
        
        return $username
    }
    catch {
        $errorMsg = "拼音转换失败: $_"
        if ($script:textPinyin) { $script:textPinyin.Text = $errorMsg }
        return $errorMsg
    }
}
