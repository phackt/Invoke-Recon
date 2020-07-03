<#
    Dirty script for powershell AD enumeration / quickwins using PowerView, PowerUpSql and Windows ActiveDirectory modules
    
    Author: @phackt_ul
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>

#Requires -Version 2

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [String]$Domain
)

<#
    Importing custom modules
#>
Import-Module .\modules\GadgetExchange.psm1

if ((Get-Module -Name "GadgetExchange") -eq $null){
    Write-Error "[!] .\modules\GadgetExchange.psm1 not found, Exchange Servers enumeration will not be processed"
}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# Main  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

function Write-Banner {
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [string]$Text
    )

    $Output = "`r`n`r`n"
    $Output += "+------+------------------------------------------------+------+`r`n"
    $Output += "| $Text `r`n"
    $Output += "+------+------------------------------------------------+------+"

    Write-Output $Output
    
}

function Write-BigBanner {
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [string]$Text
    )

    $Output = "`r`n`r`n"
    $Output += "################################################################`r`n"
    $Output += "################################################################`r`n"
    $Output += "| $Text `r`n"
    $Output += "################################################################`r`n"
    $Output += "################################################################"

    Write-Output $Output
    
}

#
# Check Commands are available
#

if (-Not (((Get-Module -Name "*PowerSploit*") -ne $null -or (Get-Module -Name "*PowerView*") -ne $null) -and (Get-Module -Name "ActiveDirectory") -ne $null -and (Get-Module -Name "PowerUpSQL") -ne $null)){
    throw "[!] Please import the following modules: PowerView (dev branch), ActiveDirectory (ADModule) and PowerUpSQL"
}

#
# Init Aliases
#

# New-Alias -Name Export-CSV -Value "Export-CSV -NoTypeInformation -NoTypeInformation" -Scope Process
# New-Alias -Name ConvertTo-Csv -Value "ConvertTo-Csv -NoTypeInformation -NoTypeInformation" -Scope

#
# Init variables
#

$CurDir = (Get-Location).Path
$EnumDir = "$CurDir\results\$Domain\domain"
$EnumMSSQLDir = "$CurDir\results\$Domain\mssql"
$QuickWinsDir = "$EnumDir\quickwins"
$OutputDirs = @($EnumDir,$EnumMSSQLDir,$QuickWinsDir)

#
# Creating output dirs
#

foreach ($OutputDir in $OutputDirs){
    If(!(Test-Path "$OutputDir"))
    {
          New-Item -ItemType Directory -Force -Path "$OutputDir" > $null
    }
}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# Domain Enumeration  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

Write-BigBanner -Text "Starting enumeration of domain $Domain"

Write-Banner -Text "Looking for PDC"
$PDC = Resolve-DnsName -DnsOnly -Type SRV _ldap._tcp.pdc._msdcs.$Domain
Write-Output $PDC

Write-Banner -Text "Looking for all DCs"
$AllDCs = Resolve-DnsName -DnsOnly -Type SRV _ldap._tcp.dc._msdcs.$Domain
Write-Output $AllDCs

Write-Banner -Text "Checking spooler service is up on DCs"
foreach($DCip in $AllDCs.IP4Address){
    Write-Output "[+] ls \\$DCip\pipe\spoolss"
    ls \\$DCip\pipe\spoolss
}

$RootDSE = Get-ADRootDSE -Server $PDC.IP4Address

# Test if RootDSE is null to construct the namingContext
if ($RootDSE -eq $null){
    Write-Output "[!] Root DSE can not be retrieved !"
}

Write-Banner -Text "Members of the DCs 'Domain Local' group Administrators"
foreach($DCip in $AllDCs.IP4Address){
    Write-Output "[+] Digging into $DCip"
    Get-NetLocalGroupMember -ComputerName $DCip -GroupName "Administrators"
}

Write-Banner -Text "Get-DomainSID"
$DomainSID = Get-DomainSID -Domain $Domain -Server $PDC.IP4Address
Write-Output $DomainSID

Write-Banner -Text "Get-Domain"
Get-Domain -Domain $Domain

Write-Banner -Text "Get-ADForest"
$Forest = Get-ADForest -Identity $Domain -Server $PDC.IP4Address
Write-Output $Forest

$DomainPolicy = Get-DomainPolicy -Domain $Domain -Server $PDC.IP4Address

Write-Banner -Text "(Get-DomainPolicy).SystemAccess"
$DomainPolicy."SystemAccess"

Write-Banner -Text "(Get-DomainPolicy).KerberosPolicy"
$DomainPolicy."KerberosPolicy"

Write-Banner -Text "Get-DomainTrust"
Get-DomainTrust -Domain $Domain -Server $PDC.IP4Address

Write-Banner -Text "Get-ForestTrust"
Get-ForestTrust -Forest $Forest.Name

Write-Banner -Text "Get-DomainUser"
Write-Output "[saving into ""$EnumDir\users.csv""]"
Get-DomainUser -Domain $Domain -Server $PDC.IP4Address | Export-CSV -NoTypeInformation -Path "$EnumDir\users.csv"

Write-Banner -Text "Get-DomainGroup"
Write-Output "[saving into ""$EnumDir\groups.csv""]"
Get-DomainGroup -Domain $Domain -Server $PDC.IP4Address | Export-CSV -NoTypeInformation -Path "$EnumDir\groups.csv"

Write-Banner -Text "Get-DomainComputer"
Write-Output "[saving into ""$EnumDir\computers.csv""]"
Get-DomainComputer -Domain $Domain -Server $PDC.IP4Address | Export-CSV -NoTypeInformation -Path "$EnumDir\computers.csv"

#
# Privileged accounts
#

Write-Banner -Text "Nested privileged users (RID >= 1000)"
<#
    From these Privileged Groups:
    "Administrators",        
    "Domain Admins",       
    "Enterprise Admins",   
    "Schema Admins",       
    "Account Operators",   
    "Backup Operators"
#>

$AdministratorsGroup = Get-DomainGroup -Domain $Domain -Identity "S-1-5-32-544"
$DomainAdminsGroup = Get-DomainGroup -Domain $Domain -Identity "$DomainSID-512"
$EnterpriseAdminsGroup = Get-DomainGroup -Domain $Domain -Identity "$DomainSID-519"
$SchemaAdminsGroup = Get-DomainGroup -Domain $Domain -Identity "$DomainSID-518"
$AccountOperatorsGroup = Get-DomainGroup -Domain $Domain -Identity "S-1-5-32-548"
$BackupOperatorsGroup = Get-DomainGroup -Domain $Domain -Identity "S-1-5-32-551"

$AdministratorsGroup.objectsid,$DomainAdminsGroup.objectsid,$EnterpriseAdminsGroup.objectsid,$SchemaAdminsGroup.objectsid,$AccountOperatorsGroup.objectsid,$BackupOperatorsGroup.objectsid | Get-DomainGroupMember -Recurse -Domain $Domain -Server $PDC.IP4Address 2> $null | Where-Object {($_.MemberObjectClass -eq "user") -and ([int]$_.MemberSID.split("-")[7] -ge 1000)} | Sort MemberSID -Unique | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumDir\privileged_accounts.csv" | ConvertFrom-Csv

<#
foreach($pa in $PrivilegedAccounts){

#
# Can be delegated ?
#

#
# Has delegation ?
#

#
# Can be AS_REP Roastable ?
#

#
# Is kerberoastable ?
#

#
# Has Replicating Directory Changes / Replicating Directory Changes All ?
#

#
# permissive ACLs on it
#

#
# logon sessions
#

#
# others ...
#

}
#>

#
# Exchange servers
#

Write-Banner -Text "Looking for Exchange servers"
# Only keeping for now CN=ms-Exch-Exchange-Server
$ExchangeServers = Get-ADExchangeServer -ConfigurationNamingContext $RootDSE.configurationNamingContext -Server $PDC.IP4Address | Where-Object {$_.Category -like "CN=ms-Exch-Exchange-Server*"} | Select-Object Version,FQDN,Roles,Class
$ExchangeServers | Export-CSV -NoTypeInformation -Path "$EnumDir\exchange_servers.csv"

# Looking for [PrivExchange, CVE-2020-0688]
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190007
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0688
# https://docs.microsoft.com/fr-fr/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019

foreach($ExchangeServer in $ExchangeServers){

    ##################################################################################
    #PrivExchange
    $PrivExchange = $true
    switch($ExchangeServer.MajorVersion)
    {
        "15" {
                switch($ExchangeServer.MinorVersion)
                {
                    "2" {if([int]$ExchangeServer.Build -ge 330){$CVE20200688 = $false};Break}
                    "1" {if([int]$ExchangeServer.Build -ge 1713){$CVE20200688 = $false};Break}
                    "0" {if([int]$ExchangeServer.Build -ge 1473){$CVE20200688 = $false};Break}
                }
                Break
             }
        "14" {
                switch($ExchangeServer.MinorVersion)
                {
                    "3" {if([int]$ExchangeServer.Build -ge 442){$CVE20200688 = $false};Break}
                }
                Break
             }
    }

    $ExchangeServer | Add-Member -MemberType NoteProperty -Name PrivExchange -Value $PrivExchange
    ##################################################################################

    ##################################################################################
    #CVE-2020-0688
    $CVE20200688 = $true
    switch($ExchangeServer.MajorVersion)
    {
        "15" {
                switch($ExchangeServer.MinorVersion)
                {
                    "2" {if([int]$ExchangeServer.Build -ge 464){$CVE20200688 = $false};Break}
                    "1" {if([int]$ExchangeServer.Build -ge 1847){$CVE20200688 = $false};Break}
                    "0" {if([int]$ExchangeServer.Build -ge 1497){$CVE20200688 = $false};Break}
                }
                Break
             }
        "14" {
                switch($ExchangeServer.MinorVersion)
                {
                    "3" {if([int]$ExchangeServer.Build -ge 496){$CVE20200688 = $false};Break}
                }
                Break
             }
    }

    $ExchangeServer | Add-Member -MemberType NoteProperty -Name CVE-2020-0688 -Value $CVE20200688
    ##################################################################################

    Write-Output $ExchangeServer

    #Checking if server is vuln
    if($ExchangeServer.PrivExchange -eq $true){
        Write-Host -ForegroundColor yellow "[!] Exchange server $($ExchangeServer.FQDN) vulnerable to PrivExchange"
    }

    #Checking if server is vuln
    if($ExchangeServer.'CVE-2020-0688' -eq $true){
        Write-Host -ForegroundColor yellow "[!] Exchange server $($ExchangeServer.FQDN) vulnerable to CVE-2020-0688"
    }
}

Write-Banner -Text "Looking for users having a mailbox"
Write-Output "[saving into ""$EnumDir\users_with_mailbox.csv""]"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -LDAPFilter "(msExchMailboxGuid=*)" | Export-CSV -NoTypeInformation -Path "$EnumDir\users_with_mailbox.csv"


# ----------------------------------------------------------------
# ----------------------------------------------------------------
# Interesting stuff 
# ----------------------------------------------------------------
# ----------------------------------------------------------------

Write-BigBanner -Text "Looking for interesting stuff"

#
# Deprecated OS
#

Write-Banner -Text "End-of-support Operating Systems (MS17-010)"
Get-DomainComputer -Domain $Domain -Server $PDC.IP4Address |  Where-Object {($_.OperatingSystem -like "*XP*") -or ($_.OperatingSystem -like "*Vista*") -or ($_.OperatingSystem -like "*2003*") -or ($_.OperatingSystem -like "*Windows 7*") -or ($_.OperatingSystem -like "*Windows 8*")} | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\deprecated_os.csv" | ConvertFrom-Csv 

#
# Kerberoast
#

Write-Banner -Text "All kerberoastable users"
Get-DomainUser -SPN -Domain $Domain -Server $PDC.IP4Address | Where-Object {$_.samaccountname -ne 'krbtgt'} | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\kerberoastable_all.csv" | ConvertFrom-Csv

Write-Banner -Text "Kerberoastable users members of DA"
Get-DomainUser -SPN -Domain $Domain -Server $PDC.IP4Address | ?{$_.memberof -match $DomainAdminsGroup.samaccountname -and $_.samaccountname -ne 'krbtgt'} | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\kerberoastable_da.csv" | ConvertFrom-Csv

#
# AS_REP Roasting - no kerberos preauth
#

Write-Banner -Text "Users without kerberos preauth"
Get-DomainUser -PreauthNotRequired -Domain $Domain -Server $PDC.IP4Address | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\users_without_krb_preauth.csv" | ConvertFrom-Csv

#
# Kerberos delegation - unconstrained
#

Write-Banner -Text "Computers with unconstrained delegation - skip DCs"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {(TrustedForDelegation -eq $True) -AND (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\unconstrained_computers.csv" | ConvertFrom-Csv

Write-Banner -Text "Users with unconstrained delegation"
Get-ADUSer -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\unconstrained_users.csv" | ConvertFrom-Csv

Write-Banner -Text "Managed Service Accounts with unconstrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\unconstrained_msa.csv" | ConvertFrom-Csv

#
# Kerberos delegation - constrained
#

Write-Banner -Text "Computers with constrained delegation"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_computers.csv" | ConvertFrom-Csv

Write-Banner -Text "Users with constrained delegation"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_users.csv" | ConvertFrom-Csv

Write-Banner -Text "Managed Service Accounts with constrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_msa.csv" | ConvertFrom-Csv

#
# Kerberos delegation - constrained with protocol transition
#

Write-Banner -Text "Computers with constrained delegation and protocol transition"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_t2a4d_computers.csv" | ConvertFrom-Csv

Write-Banner -Text "Users with constrained delegation and protocol transition"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_t2a4d_users.csv" | ConvertFrom-Csv

Write-Banner -Text "Managed Service Accounts with constrained delegation and protocol transition"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\constrained_t2a4d_msa.csv" | ConvertFrom-Csv

#
# Find services with msDS-AllowedToActOnBehalfOfOtherIdentity
#

Write-Banner -Text "Finding services with msDS-AllowedToActOnBehalfOfOtherIdentity"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\actonbehalf_computers.csv" | ConvertFrom-Csv

Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\actonbehalf_users.csv" | ConvertFrom-Csv

Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $PDC.IP4Address -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$QuickWinsDir\actonbehalf_msa.csv" | ConvertFrom-Csv


#
# Find principals (RID >= 1000) with Replicating Directory Changes / Replicating Directory Changes All
#

Write-Banner -Text "Finding principals with replicating permissions"
$DefaultNamingContext = $RootDSE.defaultNamingContext
cd "AD:\$DefaultNamingContext"

if ((Get-Location).Path -eq "$CurDir"){
    Get-DomainObjectAcl $RootDSE.defaultNamingContext -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get')}
} else
{
    $AllReplACLs = (Get-AcL).Access | Where-Object {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'}

    #Filter this list to RIDs above 1000 which will exclude well-known Administrator groups
    foreach ($ACL in $AllReplACLs)
    {
        $user = New-Object System.Security.Principal.NTAccount($ACL.IdentityReference)
        $SID = $user.Translate([System.Security.Principal.SecurityIdentifier])
        $RID = $SID.ToString().Split("f-")[7]
        if([int]$RID -ge 1000)
        {
            Write-Output "[+] Permission to Sync AD granted to:" $ACL.IdentityReference
            # $ACL.RemoveAccessRule($ACL.Access)
        }
    }

    cd "$CurDir"
}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# MSSQL Enumeration  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

Write-BigBanner -Text "Starting enumeration of MSSQL instances"

#
# MSSQL enumeration
#

Write-Banner -Text "Enumerate MSSQL instances (looking for SPN service class MSSQL)"
$AllSQLInstances = Get-SQLInstanceDomain -IncludeIP -DomainController $PDC.IP4Address
$AllSQLInstances | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumDir\instances.csv" | ConvertFrom-Csv

Write-Banner -Text "Are MSSQL instances accessible ?"
$Instances = $AllSQLInstances | Get-SQLConnectionTestThreaded
$AccessibleInstances = New-Object System.Collections.Generic.HashSet[String]
foreach($Instance in $Instances){
    if($Instance.Status -eq "Accessible"){

        #
        # Avoid doublon - instance vs instance,1433
        #

        if ($Instance.Instance -notmatch ".*,[0-9]+") 
        {
            $AccessibleInstances.Add("$($Instance.Instance),1433") > $null
        } else {
            $AccessibleInstances.Add("$($Instance.Instance)") > $null
        }
    }
}

#
# Create result directory instance
#

foreach($Instance in $AccessibleInstances){
    If(!(Test-Path "$EnumMSSQLDir\$Instance"))
    {
          New-Item -ItemType Directory -Force -Path "$EnumMSSQLDir\$Instance" > $null
    }
}

Write-Output $Instances

Write-Banner -Text "Find MSSQL instances versions"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Get-SQLServerInfo -Instance $Instance | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\version.csv" | ConvertFrom-Csv
}

Write-Banner -Text "Find linked servers from each accessible MSSQL instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Get-SQLServerLinkCrawl -Instance $Instance | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\linked_servers.csv" | ConvertFrom-Csv
}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# MSSQL Audit  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

Write-BigBanner -Text "Auditing MSSQL instances"

#
# MSSQL audit
#

Write-Banner -Text "MSSQL instances common credentials bruteforce"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Get-SQLServerLoginDefaultPw -Instance $Instance | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\bruteforce_creds.csv" | ConvertFrom-Csv
}

Write-Banner -Text "Is xp_cmdshell enabled through linked servers of each accessible instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Get-SQLServerLinkCrawl -Instance $Instance -Query "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS 'is_XpCmdShell' FROM master.sys.configurations WHERE name like '%cmd%';" |
 select Version,Instance,Sysadmin,User -ExpandProperty CustomQuery | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\linked_servers_xp_cmdshell_enabled.csv" | ConvertFrom-Csv
}

Write-Banner -Text "Auditing each accessible MSSQL Instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Invoke-SQLAudit -Instance $Instance | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\audit.csv" | ConvertFrom-Csv
}
