# powershell

$normal_secedit = [ordered]@{
        'export'    =   { secedit.exe /export /cfg .\secedit.cfg };
        'remove'    =   { Remove-Item -force .\secedit.cfg -confirm:$false };
        'push'      =   { secedit.exe /configure /db c:\windows\security\local.sdb /cfg .\secedit.cfg /areas USER_RIGHTS };
}

$privilegeName = [ordered]@{
    'Generate Security Audits'  =   'SeAuditPrivilege'; #2.2.30
    'Replace process lvl token' =   'SeAssignPrimaryTokenPrivilege'; #2.2.44
    'backup files directory'    =   'SeBackupPrivilege'; #2.2.10
    'Log batch job'             =   'SeBatchLogonRight'; #2.2.36
    'global objects'            =   'SeCreateGlobalPrivilege'; #2.2.15
    'pagefile'                  =   'SeCreatePagefilePrivilege'; #2.2.13
    'Permanent Privilege'       =   'SeCreatePermanentPrivilege'; #2.2.16
    'Symbolic links'            =   'SeCreateSymbolicLinkPrivilege'; #2.2.17
    'token privilege'           =   'SeCreateTokenPrivilege'; #2.2.14
    'Debug programs'            =   'SeDebugPrivilege'; #2.2.19
    'Deny logon batch job'      =   'SeDenyBatchLogonRight'; #2.2.22
    'Deny logon locally'        =   'SeDenyInteractiveLogonRight'; #2.2.24
    'Deny Network Logon Rights' =   'SeDenyNetworkLogonRight'; #2.2.20 + 2.2.21
    'Deny logon RDP'            =   'SeDenyRemoteInteractiveLogonRight'; #2.2.25 + 2.2.26
    'Deny Service logon'        =   'SeDenyServiceLogonRights'; #2.2.23
    'Enable Delegate Priv'      =   'SeEnableDelegationPrivilege'; # 2.2.27 + 2.2.28
    'Priv Impersonate'          =   'SeImpersonatePrivilege';# 2.2.31 2.2.32
    'Increase schedule'         =   'SeIncreaseBasePriorityPrivilege'; #2.2.33
    'memory quota'              =   'SeIncreaseQuotaPrivilege'; #2.2.6
    'log locally'               =   'SeInteractiveLogonRight'; # 2.2.7
    'Device Drivers'            =   'SeLoadDriverPrivilege'; #2.2.34
    'Lock pages memory'         =   'SeLockMemoryPrivilege'; #2.2.35
    'add workstation domain'    =   'SeMachineAccountPrivilege';
    'volume maint tasks'        =   'SeManageVolumePrivilege'; #2.2.41
    'Access Computer Network'   =   'SeNetworkLogonRight';
    'profile single process'    =   'SeProfileSingleProcessPrivilege'; #2.2.42
    'Modify object label'       =   'SeRelabelPrivilege'; # 2.2.39
    'remote desktop services'   =   'SeRemoteInteractiveLogonRight'; #2.2.8 + 2.2.9
    'Remote Force shutdown'     =   'SeRemoteShutdownPrivilege'; #2.2.29
    'Restore files and dir'     =   'SeRestorePrivilege'; #2.2.45
    'Manage Audit Security log' =   'SeSecurityPrivilege'; #2.2.37 + 2.2.38
    'Shutdown system'           =   'SeShutdownPrivilege'; #2.2.46
    'Sync dir service data'     =   'SeSyncAgentPrivilege'; #2.2.47
    'firmware environment'      =   'SeSystemEnvironmentPrivilege'; # 2.2.40
    'profile sys performance'   =   'SeSystemProfilePrivilege'; #2.2.43
    'system time'               =   'SeSystemtimePrivilege'; #2.2.11
    'Take ownership'            =   'SeTakeOwnershipPrivilege'; #2.2.48
    'Act OS'                    =   'SeTcbPrivilege'; #2.2.4
    'time zone'                 =   'SeTimeZonePrivilege'; #2.2.12
    'Access Credential Manager' =   'SeTrustedCredManAccessPrivilege'; #2.2.1
}

$group = @(
    'Administrators',
    'Authenticated Users',
    'Guests',
    'NT VIRTUAL MACHINE\Virtual Machines',
    'IIS_IUSRS',
    'Local Account',
    'NETWORK SERVICE',
    'Null SID',
    'Remote Desktop Users',
    'LOCAL SERVICE',
    'NT SERVICE\WdiServiceHost',
    'SERVICE',
    'Window Manager\Window Manager Group',
    'ENTERPRISE DOMAIN CONTROLLERS',
    'Exchange Servers'
)

$sqlServices = Get-Service | Where-Object { $_.DisplayName -like '*SQL Server*' -or $_.ServiceName -like '*MSSQL*' }
$IIS = Get-WindowsFeature -Name Web-Server | Select-Object -ExpandProperty Installed
$ADFS = Get-WindowsFeature -Name ADFS-Federation | Select-Object -ExpandProperty Installed

function ApplyGeneralizedBenchmark([hashtable]$replace) {
    $orderedReplace = New-Object 'System.Collections.Specialized.OrderedDictionary'
    $replace.GetEnumerator() | ForEach-Object {
        $orderedReplace.Add($_.Key, $_.Value)
    }
    foreach ($key in $orderedReplace.Keys) {
        try {
            Write-Host "Executing command '$key':"
            $privName = $orderedReplace[$key]
            $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
            (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"
    }
    Write-Host 'Pushing to secedit'
    $normal_secedit['push']
}

class RegularMS {

    [hashtable] $normal_secedit

    RegularMS([hashtable]$normal_secedit){
        $this.normal_secedit    = $normal_secedit
    }

    [void] ApplyAdministratorGroupBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
        '2.2.3 | replace | Access Computer Network'     = { 'Access Computer Network' };
        '2.2.9 | replace | Remote Desktop Service'      = { 'DC remote desktop services' }
        '2.2.18 | replace | Symbolic links'             = { 'Symbolic links' }
        '2.2.21 | replace | Deny Network Access'        = { 'Deny Network Logon Rights' }
        '2.2.32 | replace | Impersonate client '        = { 'Priv Impersonate' }
        '2.2.38 | replace | Manage Audit Security log'  = { 'Manage Audit Security log' }
        'push' = $this.normal_secedit['push'];
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.32 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] Authenticated_Users_benchmark([string]$groupName) {
        $replace = [ordered]@{
        '2.2.3 | replace | Access Computer Network' = {
            $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            'Access Computer Network'
        }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n"
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyGuestsBenchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
        '2.2.21 | replace | Deny Network Access'    =   { 'Deny Network Logon Rights' }
        '2.2.26 | replace | Deny RDP'               =   { 'Deny logon RDP' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyHyperVGroupBenchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
            '2.2.18 | replace | Symbolic links' = { 'Symbolic links' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n"
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyIIS_IUSRSGroupBenchmarks([string]$groupName, [string[]]$SQL, [string]$MIIS) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.32 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push'                                  =   { $this.normal_secedit['push']; }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.32 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                if ($key -eq '2.2.32 | replace | Impersonate client ' -and $MIIS -eq 'True'){
                    (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
                } else {
                    Write-Output 'A Web Server is not installed ... Not Applicable'
                }
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyLocalAccountBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
            '2.2.18 | replace | Symbolic links'         =   { 'Symbolic links' }
            '2.2.21 | replace | Deny Network Access'    =   { 'Deny Network Logon Rights' }
            '2.2.26 | replace | Deny RDP'               =   { 'Deny logon RDP' }
            '2.2.32 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push' = $this.normal_secedit['push'];
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.32 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNetworkServiceGroupBenchmarks([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.32 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push'                                  =   { $this.normal_secedit['push']; }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.32 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNoOneGroupBenchmarks([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $policies = [ordered]@{
        '2.2.28 | replace | Enable Priv Delegation' = { 'Enable Delegate Priv' }
        }

        Write-Host "Adding benchmarks that are associated with no one group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($policies)
    }

    [void] Remote_Desktop_Users([string]$groupName){
        $replace = [ordered]@{
        '2.2.3 | replace | Access Computer Network' = {
            $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            'DC remote desktop services'
        }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n"
        ApplyGeneralizedBenchmark($replace)
    }

}

class General_benchmark {

    [hashtable] $normal_secedit
    [hashtable] $privilegeName

    General_benchmark([hashtable]$normal_secedit, [hashtable]$privilegeName){
        $this.normal_secedit    =   $normal_secedit
        $this.privilegeName     =   $privilegeName
    }

    [void] ApplyNoOneGroupBenchmarks([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Host "Adding benchmarks that are associated with the No One group`n" -ForegroundColor DarkBlue
        $replace = [ordered]@{
            '2.2.1 | replace | Access Credential Manager'   = { 'Access Credential Manager' }
            '2.2.4 | replace | Act OS'                      = { 'Act OS' }
            '2.2.14 | replace | token privilege'            = { 'token privilege' }
            '2.2.16 | replace | Permanent objects'          = { 'Permanent Privilege' }
            '2.2.35 | replace | lock pages memory'          = { 'Lock pages memory' }
            '2.2.39 | replace | object label'               = { 'Modify object label' }
            # 'push' = { $this.normal_secedit['push'] }
        }
        ApplyGeneralizedBenchmark($replace)
        
    }

    [void] ApplyAdministratorGroupBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.6 | replace | memory quota' = { 'memory quota' }
            '2.2.7 | replace | log locally' = { 'log locally' }
            '2.2.10 | replace | backup files directory' = { 'backup files directory' }
            '2.2.11 | replace | system time privilege' = { 'system time' }
            '2.2.12 | replace | time zone' = { 'time zone' }
            '2.2.13 | replace | pagefile' = { 'page file' }
            '2.2.15 | replace | global objects' = { 'global objects' }
            '2.2.19 | replace | Debug Programs' = { 'Debug Programs' }
            '2.2.29 | replace | Force shutdown remote system' = { 'Remote Force shutdown' }
            '2.2.33 | replace | Increase Schedule priority' = { 'Increase schedule' }
            '2.2.34 | replace | Load/unload device driver' = { 'Device Drivers' }
            '2.2.40 | replace | modify firmware env'        = { 'firmware environment' }
            '2.2.41 | replace | volume maint tasks'         = { 'volume maint tasks' }
            '2.2.42 | replace | profile single process'     = { 'profile single process' }
            '2.2.43 | replace | profile system performance' = { 'profile sys performance' }
            '2.2.45 | replace | Restore files and dirs'     = { 'Restore files and dir' }
            '2.2.46 | replace | shut down the system'       = { 'Shutdown system' }
            '2.2.48 | replace | take ownership'             = { 'Take ownership' }
            'push' = { $this.normal_secedit['push'] }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.15 | replace | global objects' -and $SQL.Count -gt 0){
                    Write-Host "$key is Not Applicable ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] Authenticated_Users_grp_benchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.2 | 2.2.3 | replace | Access Computer Network' = { 'Access Computer Network' }
            'push' = { $this.normal_secedit['push'] }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyLocalServiceGroupBenchmark([string]$groupName, [string[]]$SQL, [string]$MIIS, [string]$ADFS) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.6 | replace | memory quota'                =   { 'memory quota' }
            '2.2.11 | replace | system time privilege'      =   { 'system time' }
            '2.2.12 | replace | time zone'                  =   { 'time zone' }
            '2.2.15 | replace | global objects'             =   { 'global objects' }
            '2.2.30 | replace | Generate security audits'   =   { 'Generate Security Audits' }
            '2.2.44 | replace | Replace process lvl token'  =   { 'Replace process lvl token' }
            'push'                                          =   { $this.normal_secedit['push']; }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.15 | replace | global objects' -and $SQL.Count -gt 0){
                    Write-Host "$key is Not Applicable ... Skipping"
                }
                if ($key -eq '2.2.30 | replace | Generate security audits' -and ($MIIS -eq 'True' -or $ADFS -eq 'True' )){
                    Write-Host "$key needs an exception ... Skipping"
                }
                if ($key -eq '2.2.44 | replace | Replace process lvl token' -and ($MIIS -eq 'True' -or $SQL.Count -gt 0 )){
                    Write-Host "$key needs an exception ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNetworkServiceGroupBenchmarks([string]$groupName, [string[]]$SQL, [string]$MIIS, [string]$ADFS) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.6 | replace | memory quota'                =   { 'memory quota' }
            '2.2.15 | replace | global objects'             =   { 'global objects' }
            '2.2.30 | replace | Generate security audits'   =   { 'Generate Security Audits' }
            '2.2.44 | replace | Replace process lvl token'  =   { 'Replace process lvl token' }
            'push'                                          =   { $this.normal_secedit['push']; }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.15 | replace | global objects' -and $SQL.Count -gt 0){
                    Write-Host "$key is Not Applicable ... Skipping"
                }
                if ($key -eq '2.2.30 | replace | Generate security audits' -and ($MIIS -eq 'True' -or $ADFS -eq 'True' )){
                    Write-Host "$key needs an exception ... Skipping"
                }
                if ($key -eq '2.2.44 | replace | Replace process lvl token' -and ($MIIS -eq 'True' -or $SQL.Count -gt 0 )){
                    Write-Host "$key needs an exception ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNTServiceWdiServiceHostBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.43 | replace | profile system performance' = { 'profile sys performance' }
            'push' = { $this.normal_secedit['push'] }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.15 | replace | global objects' -and $SQL.Count -gt 0){
                    Write-Host "$key is Not Applicable ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] service_grp_benchmarks([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
            '2.2.15 | replace | global objects' = { 'global objects' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyGuestsBenchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
        '2.2.22 | replace | Deny logon batch job'   =   { 'Deny logon batch job' }
        '2.2.23 | replace | Deny logon service job'   =   { 'Deny Service logon' }
        '2.2.24 | replace | Deny logon locally'   =   { 'SeDenyInteractiveLogonRight' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyWindowsManagerGroupBenchmarks([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.33 | replace | Increase Schedule priority' = { 'Increase schedule' }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }
}

class DomCon {
    [hashtable] $normal_secedit
    [hashtable] $privilegeName

    DomCon([hashtable]$normal_secedit, [hashtable] $privilegeName){
        $this.normal_secedit = $normal_secedit
        $this.privilegeName = $privilegeName
    }

    [void] ApplyAdministratorGroupBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.2 | replace | Access Computer Network'     = { 'Access Computer Network' }
            '2.2.5 | replace | Add workstation domain'      = { 'add workstation domain' }
            '2.2.8 | replace | Remote Desktop Service'      = { 'remote desktop services' }
            '2.2.17| replace | Symbolic links'              = { 'Symbolic links' }
            '2.2.27 | replace | Enable Priv Delegation'     = { 'Enable Delegate Priv' }
            '2.2.31 | replace | Impersonate client '        = { 'Priv Impersonate' }
            '2.2.36 | replace | Log on as a batch job'      = { 'Log batch job' }
            '2.2.37 | replace | Manage Audit Security log'   = { 'Manage Audit Security log' }
            'push' =  { $this.normal_secedit['push'] }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.31 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] Authenticated_Users_benchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
        '2.2.2 | replace | Access Computer Network' = { 'Access Computer Network' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ENTERPRISE_DOMAIN_CONTROLLERS_benchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
        '2.2.2 | replace | Access Computer Network' =   { 'Access Computer Network' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyExchangeServerBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.37 | replace | Manage Audit Security log'   = { 'Manage Audit Security log' }
            'push'                                           =  { $this.normal_secedit['push'] }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.31 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyGuestsBenchmark([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
        '2.2.20 | replace | Deny Network Access'    =   { 'Deny Network Logon Rights' }
        '2.2.25 | replace | Deny RDP'               =   { 'Deny logon RDP' }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($replace)
    }

    [void] ApplyLocalServiceGroupBenchmark([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.31 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push'                                          =   { $this.normal_secedit['push']; }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.31 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNetworkServiceGroupBenchmarks([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value

        $replace = [ordered]@{
            '2.2.31 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push'                                  =   { $this.normal_secedit['push']; }
        }
        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.31 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

    [void] ApplyNoOneGroupBenchmarks([string]$groupName) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $policies = [ordered]@{
        '2.2.47 | replace | Sync dir service data' = { 'Sync dir service data' }
        }

        Write-Host "Adding benchmarks that are associated with no one group`n" -ForegroundColor DarkBlue
        ApplyGeneralizedBenchmark($policies)
    }

    [void] service_grp_benchmarks([string]$groupName, [string[]]$SQL) {
        $sid = (New-Object System.Security.Principal.NTAccount($groupName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $replace = [ordered]@{
            '2.2.31 | replace | Impersonate client '    = { 'Priv Impersonate' }
            'push'                                      = { $this.normal_secedit['push']; }
        }

        Write-Host "Adding benchmarks that are associated with the $groupName group`n" -ForegroundColor DarkBlue
        foreach ($key in $replace.Keys) {
            try {
                Write-Host "Executing command '$key':"
                $privName = $replace[$key]
                if ($key -eq '2.2.31 | replace | Impersonate client ' -and $SQL.Count -gt 0){
                    Write-Host "$key needs an exception to this rule ... Skipping"
                }
                $pattern = "($($this.privilegeName[$privName]) = \[.*?)(\r\n)"
                (Get-Content .\secedit.cfg) -replace $pattern, "`$1,$sid`$2"
            } catch {
                Write-Host "Error executing command: $_"
            }
            Write-Host "----------------------"
        }
    }

}

# understanding domain numbers
# 0: Standalone Workstation
# 1: Member Workstation
# 2: Standalone Server
# 3: Member Server
# 4: Backup Domain Controller (BDC)
# 5: Primary Domain Controller (PDC)
# 6: Backup Domain Controller (BDC) running as a member server
# 7: Domain Controller

function ApplyGeneralBenchmarks{
    $General_benchmark = [General_benchmark]::new($normal_secedit,$privilegeName)
    Write-Output 'General benchmarks'`n
    $General_benchmark.ApplyNoOneGroupBenchmarks($group[7])
    $General_benchmark.ApplyAdministratorGroupBenchmark($group[0],$sqlServices)
    $General_benchmark.Authenticated_Users_grp_benchmark($group[1])
    $General_benchmark.ApplyLocalServiceGroupBenchmark($group[9],$sqlServices, $IIS, $ADFS)
    $General_benchmark.ApplyNetworkServiceGroupBenchmarks($group[6], $sqlServices, $IIS, $ADFS)
    $General_benchmark.service_grp_benchmarks($group[11])
    $General_benchmark.ApplyWindowsManagerGroupBenchmarks($group[12])
    $General_benchmark.ApplyNTServiceWdiServiceHostBenchmark($group[10],$sqlServices)
}

function ApplyDomainControllerBenchmarks{
    $DomCon = [DomCon]::new($normal_secedit, $privilegeName)
    Write-Output 'DC benchmarks'`n
    $DomCon.ApplyAdministratorGroupBenchmark($group[0],$sqlServices)
    $DomCon.ENTERPRISE_DOMAIN_CONTROLLERS_benchmark($group[13])
    $DomCon.Authenticated_Users_benchmark($group[1])
    $DomCon.ApplyGuestsBenchmark($group[2])
    $DomCon.ApplyNoOneGroupBenchmarks($group[7])
    $DomCon.ApplyLocalServiceGroupBenchmark($group[9],$sqlServices)
    $DomCon.ApplyNetworkServiceGroupBenchmarks($group[6],$sqlServices)
    $DomCon.service_grp_benchmarks($group[11],$sqlServices)
    if ($ExchangeServerInstalled -eq "True") {
        $DomCon.ApplyExchangeServerBenchmark($group[14],$sqlServices)
    }
}

function ApplyRegularMSBenchmarks{
    $RegularMS = [RegularMS]::new($normal_secedit)
    Write-Output 'RegularMS benchmarks'`n
    $RegularMS.ApplyAdministratorGroupBenchmark($group[0],$sqlServices)
    $RegularMS.Authenticated_Users_benchmark($group[1])
    $RegularMS.Remote_Desktop_Users($group[8])
    if ($hyperVInstalled) {
        $RegularMS.ApplyHyperVGroupBenchmark($group[3])
    }
    $RegularMS.ApplyLocalAccountBenchmark($group[5],$sqlServices)
    $RegularMS.ApplyGuestsBenchmark($group[2])
    $RegularMS.ApplyNoOneGroupBenchmarks($group[7])
    $RegularMS.ApplyIIS_IUSRSGroupBenchmarks($group[4],$sqlServices, $ISS)
    $RegularMS.ApplyNetworkServiceGroupBenchmarks($group[6],$sqlServices)
}

function main{
    $computerSystem = Get-CimInstance -Class Win32_ComputerSystem
    $hyperVInstalled = Get-WindowsFeature -Name Hyper-V | Select-Object -ExpandProperty Installed
    $ExchangeServerInstalled = (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) -ne $null

    & $normal_secedit['export']
    & ApplyGeneralBenchmarks
    if ($computerSystem.DomainRole -ge 4) {
        & ApplyDomainControllerBenchmarks
    } else {
        & ApplyRegularMSBenchmarks
    }
    & $normal_secedit['remove']
}
main