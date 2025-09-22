<# 
�����Ӳ���
#>

# ȫ��״̬����
$script:domainContext = $null
$script:remoteSession = $null
$script:currentOU = $null
$script:allUsersOU = $null
$script:allUsers = New-Object System.Collections.ArrayList
$script:allGroups = New-Object System.Collections.ArrayList
$script:connectionStatus = "δ���ӵ���"
$script:userCountStatus = "0"
$script:groupCountStatus = "0"

function Connect-ToDomain {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    $requestData = Read-RequestData $context

    if (-not $requestData -or -not $requestData.domain -or -not $requestData.adminUser -or -not $requestData.adminPassword) {
        Send-JsonResponse $response 400 @{ success = $false; message = "���ṩ���ַ������Ա�˺ź�����" }
        return
    }

    try {
        $domain = $requestData.domain
        $adminUser = $requestData.adminUser
        $adminPassword = $requestData.adminPassword

        # ������ȫ����
        $securePassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($adminUser, $securePassword)
        
        # ����Զ�̻Ự
        $script:remoteSession = New-PSSession -ComputerName $domain -Credential $credential -ErrorAction Stop
        $script:connectionStatus = "������֤Զ�̷�����AD����..."

        # Զ����֤ADģ��
        $domainInfo = Invoke-Command -Session $script:remoteSession -ScriptBlock {
            Import-Module ActiveDirectory -ErrorAction Stop
            return Get-ADDomain -ErrorAction Stop
        } -ErrorAction Stop
        
        $script:domainContext = @{
            Server = $domain
            Credential = $credential
            DomainInfo = $domainInfo
        }
        
        # ����Ĭ��OU
        $script:currentOU = "CN=Users,$($domainInfo.DefaultPartition)"
        
        $script:connectionStatus = "�����ӵ���: $domain"
        
        # �����û������б�
        LoadUserList
        LoadGroupList

        Send-JsonResponse $response 200 @{ 
            success = $true 
            message = "���ӳɹ�"
            domainInfo = @{
                Name = $domainInfo.Name
                DNSRoot = $domainInfo.DNSRoot
                DefaultPartition = $domainInfo.DefaultPartition
            }
            currentOU = $script:currentOU
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "WinRM") { 
            $errorMsg += "`n��ȷ��Զ�̷�����������WinRM���񣬿�������winrm quickconfig����" 
        }
        elseif ($errorMsg -match "ActiveDirectory") { 
            $errorMsg += "`n��ȷ��Զ�̷������Ѱ�װADģ��" 
        }
        
        $script:connectionStatus = "����ʧ��: $errorMsg"
        $script:domainContext = $null
        $script:remoteSession = $null
        
        Send-JsonResponse $response 500 @{ 
            success = $false 
            message = $errorMsg
        }
    }
}

function Disconnect-FromDomain {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response

    $script:domainContext = $null
    $script:allUsers.Clear()
    $script:allGroups.Clear()
    $script:allOUs = $null
    $script:currentOU = $null
    
    # �ر�Զ�̻Ự
    if ($script:remoteSession) {
        Remove-PSSession $script:remoteSession
        $script:remoteSession = $null
    }

    $script:connectionStatus = "δ���ӵ���"
    $script:userCountStatus = "0"
    $script:groupCountStatus = "0"

    Send-JsonResponse $response 200 @{ 
        success = $true 
        message = "�ѳɹ��Ͽ�����"
    }
}

function Get-ConnectionStatus {
    param([System.Net.HttpListenerContext]$context)

    $response = $context.Response
    
    $isConnected = $null -ne $script:domainContext
    
    Send-JsonResponse $response 200 @{ 
        isConnected = $isConnected
        status = $script:connectionStatus
        currentOU = $script:currentOU
        userCount = $script:userCountStatus
        groupCount = $script:groupCountStatus
    }
}