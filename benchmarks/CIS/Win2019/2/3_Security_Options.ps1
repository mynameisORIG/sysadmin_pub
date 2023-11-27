# powershell

$computerSystem = Get-CimInstance -Class Win32_ComputerSystem

$registryLocation = @{
    'Accounts'                              =   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' # 2.3.1.X
    'Audit'                                 =   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' #2.3.2.X
    'Removeable Devices'                    =   'HKLM:\SYSTEM\CurrentControlSet\Services\cdrom' #2.3.4.1
    'PreventUsersInstallingPrinterDrivers'  =   'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' #2.3.4.2
}

$values = @(
        0, #disabled
        1, #enabled
        'Administrator', #2.3.1.4
        'gu3$t$', #2.3.1.5
)

function registryEditor([string]$HKLM_Location,[string]$s3c3d1tNam3,[string]$valu3s) {
    Set-ItemProperty -Path $HKLM_Location -Name $s3c3d1tNam3 -Value $valu3s
}

function Accounts {
    
    $seceditName = @(
        'NoConnectedUser',
        'EnableGuestAccount',
        'LimitBlankPasswordUse',
        'NewAdministratorName',
        'NewGuestAccountName'
    )

    $valuesDic = [ordered]@{
        '2.3.1.1 | replace | Block Microsoft accounts'                                          =   { $values[1] }
        '2.3.1.2 | replace | Guest account status'                                              =   { $values[0] }
        '2.3.1.3 | replace | limit local account use of blank passwords to console logon only'  =   { $values[1] }
        '2.3.1.4 | Accounts | Rename administrator account'                                     =   { $values[1] }
        '2.3.1.5 | Accounts | Rename Guest account'                                             =   { $values[1] }
    }

    Write-Output 'Executing Accounts benchmarks'`n
    for ($i=0; $i -lt $valuesDic.Keys.Count; $i++) {
        $key = $valuesDic.Keys[$i]
        $value = $valuesDic[$key]
        $nam3 = $seceditName[$i]
        try {
            Write-Host "Executing '$key':"`n
            if ($key -eq '2.3.1.2 | replace | Guest account status' -and $computerSystem.DomainRole -ge 4) {
                Write-Output 'This benchmark does not meet the requirements ... Not Applicable'
            } else {
                registryEditor $registryLocation['Accounts']  $nam3 $value
            }
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"    
    }
}

function Audit {
    
    $seceditName = @(
        'AuditForceSubcategoryOverride',
        'ShutdownIfUnableToLogSecurityAudits'
    )

    $executions = [ordered]@{
        '2.3.2.1 | replace | Force Audit Policy Subcategory Settings'   = { $values[1] }
        '2.3.1.2 | replace | Shutdown If Unable To Log Security Audits' = { $values[0] }
    }

    Write-Output 'Executing Audit benchmarks'`n
    for ($i=0; $i -lt $valuesDic.Keys.Count; $i++) {
        $key = $valuesDic.Keys[$i]
        $value = $valuesDic[$key]
        $nam3 = $seceditName[$i]
        try {
            Write-Host "Executing '$key':"`n
            registryEditor $registryLocation['Audit']  $nam3 $key
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"    
    }
}

function Devices {

    $seceditName = @(
        'UserAllowToFormatEject',
        'PreventUsersInstallingPrinterDrivers'
    )

    $executions = [ordered]@{
        '2.3.4.1 | replace | Allowed To Format and Eject removable media' = { $values[2] }
        '2.3.4.2 | replace | Prevent users from installing printer drivers' = {
            Set-ItemProperty -Path $registryLocation['PreventUsersInstallingPrinterDrivers'] -Name $seceditName[1] -Value $values[1]
        }
    }

    Write-Output 'Executing Devices benchmarks'`n
    foreach ($key in $executions.Keys) {
        for ($i=0; $i -lt $valuesDic.Keys.Count; $i++) {
        $key = $valuesDic.Keys[$i]
        $value = $valuesDic[$key]
        $nam3 = $seceditName[$i]
        try {
            Write-Host "Executing '$key':"`n
            registryEditor $registryLocation['Removeable Devices']  $nam3 $key
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"    
        }
    }
}

function DomainController {

}

function main {
    Accounts
    Audit
    Devices
    if ($computerSystem.DomainRole -ge 4){
        DomainController
    }
}

main
