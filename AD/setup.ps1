$AD_IP = Read-Host -Prompt 'Input the Active Directory IP Address: '
$Domain_Name = Read-Host -Prompt 'Enter the Domain Name you want to use'
Rename-Computer -NewName DC1
New-NetIPAddress –IPAddress $AD_IP -DefaultGateway 192.168.1.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses $AD_IP
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $Domain_Name -DomainNetBIOSName AD -InstallDNS
# press y