#powershell

function net_accounts {
    $values = @{
        '1.1.1' = 24;
        '1.1.2' = 42;
        '1.1.3' = 1;
        '1.1.4' = 14;
    }

    $net_commands = [ordered]@{
        'password history | 1.1.1' = "net accounts /uniquepw:$($values['1.1.1'])"; 
        'max password age | 1.1.2' = "net accounts /maxpwage:$($values['1.1.2'])"; 
        'minimum Password age | 1.1.3' = "net accounts /minpwage:$($values['1.1.3'])"; 
        'minimum Password length | 1.1.4' = "net accounts /MINPWLEN:$($values['1.1.4'])";
    };

    foreach ($key in $net_commands.Keys) {
        $command = $net_commands[$key]
        try {
            Write-Host "Executing command '$key':"
            Invoke-Expression -Command $command
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"
    }
}

function secedit {
    $password_complexity = [ordered]@{
        '1.1.5 | 1.1.6 | P1' = 'secedit.exe /export /cfg ./secpol.cfg';
        '1.1.5 | P2' = '(Get-Content .\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File .\secpol.cfg';
        '1.1.6 | P2' = '(Get-Content .\secpol.cfg).replace("ClearTextPassword = 1", "ClearTextPassword = 0") | Out-File .\secpol.cfg';
        '1.1.5 | 1.1.6 | P3' = 'secedit.exe /configure /db c:\windows\security\local.sdb /cfg .\secpol.cfg /areas SECURITYPOLICY';
        '1.1.5 | 1.1.6 | Remove secpol.cfg' = 'Remove-Item -force .\secpol.cfg -confirm:$false';
    }

    foreach ($key in $password_complexity.Keys) {
        $command = $password_complexity[$key]
        try {
            Write-Host "Executing command '$key':"
            Invoke-Expression -Command $command
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"
    }

}

function account_lockout {
    $registry_keys = @{
        'seclogon' = 'HKLM:\SYSTEM\CurrentControlSet\Services\Seclogon\Parameters';
    }

    $values = @{
        '1.2.1' = 30;
        '1.2.2' = 5;
        '1.2.3' = 1;
        '1.2.4' = 15;
    }

    $act_lockout = [ordered]@{
        '1.2.1 | account lockout duration 15+ minutes' = "Set-ItemProperty -Path $($registry_keys['seclogon']) -Name LockoutDuration -Value $($values['1.2.1'])";
        '1.2.2 | account lockout threshold >5 logon attempts' = "Set-ItemProperty -Path $($registry_keys['seclogon']) -Name LockoutBadCount -Value $($values['1.2.2'])";
        '1.2.3 | Administrator account lockout Enabled ' = "Set-ItemProperty -Path $($registry_keys['seclogon']) -Name AdminLockout -Value $($values['1.2.2'])";
        '1.2.4 | account lockout counter reset <=15 minutes' = "Set-ItemProperty -Path $($registry_keys['seclogon']) -Name ResetLockoutCount -Value $($values['1.2.4'])";
    }

    foreach ($key in $act_lockout.Keys) {
        $command = $act_lockout[$key]
        try {
            Write-Host "Executing command '$key':"
            Invoke-Expression -Command $command
        } catch {
            Write-Host "Error executing command: $_"
        }
        Write-Host "----------------------"
    }
}

function main {
    net_accounts
    secedit
    account_lockout
}

main
