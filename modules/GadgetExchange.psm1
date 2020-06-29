<#
    Modified version of https://gist.githubusercontent.com/IMJLA/86fc6c5ad8c34d455377698e7a871094/raw/25755c8643f1921031a37e34dde5b610d5c8d640/GadgetExchange.psm1
    @credits to https://github.com/IMJLA
#>
Function ConvertTo-ExchangeRole{
    <#
        .SYNOPSIS
            Convert the msExchCurrentServerRoles AD attribute into the Exchange Roles it represents
        .DESCRIPTION
            Performs a bitwise And comparison against a provided integer and the keys from a hard-coded dictionary
            Dictionary based on a table from a TechNet article
            https://technet.microsoft.com/en-us/library/bb123496(EXCHG.80).aspx
        .PARAMETER Roles
            Integer representing the Exchange roles held by the server. Matches the msExchCurrentServerRoles AD attribute.
        .OUTPUTS
            Returns a collection of strings representing the Exchange roles found
            Valid Outputs:
                "CAS"
                "ET"
                "HT"
                "MB"
                "UM"
        .EXAMPLE
            ConvertTo-ExchangeRole 38
        .EXAMPLE
            38 | ConvertTo-ExchangeRole
        .NOTES
    #>
    param(
        [parameter(
            Mandatory=$true,
            ValueFromPipeLine=$true)
        ]
        [int32]$Roles
    )
    begin{
        $roleDictionary = @{
            2  = "MB"
            4  = "CAS"
            16 = "UM"
            32 = "HT"
            64 = "ET"
        }
    }
    process{
        $roleDictionary.Keys | ?{$_ -bAnd $Roles} | %{$roleDictionary.Get_Item($_)}
    }
    end{
        Remove-Variable roleDictionary
    }
}

Function ConvertTo-ExchangeVersion{
    <#
        .SYNOPSIS
            Converts the versionNumber AD attribute into the Exchange versions it represents
        .DESCRIPTION
            Converts a provided 32-bit Base 10 integer to binary, then splits the binary bits according to Microsoft's structure
            http://blogs.msdn.com/b/pcreehan/archive/2009/09/21/parsing-serverversion-when-an-int-is-really-5-ints.aspx
        .PARAMETER Version
            Integer representing the Exchange Version of the server. Matches the versionNumber AD attribute.
        .OUTPUTS
            Returns an object with 5 properties containing 16-bit Base 10 integers which represent:
                Major Version #
                Minor Version #
                Build #
                Unknown Flag
                Unknown Legacy Version #
        .EXAMPLE
            ConvertTo-ExchangeVersion 1912832083
        .EXAMPLE
            1912832083 | ToExchangeVersion
    #>
    [CmdletBinding(
        SupportsShouldProcess=$false,
        ConfirmImpact="Low"
    )]
    param(
        [parameter(
            Mandatory=$true,
            ValueFromPipeLine=$true)
        ]
        [int32]$Version
    )
    begin{
        Write-Debug "$(Get-Date -Format s)`t$env:COMPUTERNAME`tConvertTo-ExchangeVersion: Input Base 10:`t$Version"
        $VersionSizeInBits = 32
    }
    process{
        $BinaryVersion = [convert]::ToString([int32]$Version,2)

        #If LegacyVersionStructure < 4 bits, [convert] does not include the preceding 0's that complete the 32-bit integer
        #We need to add them back
        Write-Debug "$(Get-Date -Format s)`t$env:COMPUTERNAME`tConvertTo-ExchangeVersion: Input Bits:`t$($BinaryVersion.Length)`t$BinaryVersion"
        for ($i=$($BinaryVersion.Length);$i -lt $VersionSizeInBits;$i++){
            $BinaryVersion = '0' + $BinaryVersion
        }
        Write-Debug "$(Get-Date -Format s)`t$env:COMPUTERNAME`tConvertTo-ExchangeVersion: Output Bits:`t$($BinaryVersion.Length)`t$BinaryVersion"
        New-Object PSObject -Property @{
            LegacyVersionStructure = [convert]::ToInt16($BinaryVersion.Substring(0,4),2) #The first 4 bits represent a number used for comparison against older version number structures.
            MajorVersion = [convert]::ToInt16($BinaryVersion.Substring(4,6),2) #The next 6 bits represent the major version number.
            MinorVersion = [convert]::ToInt16($BinaryVersion.Substring(10,6),2) #The next 6 bits represent the minor version number.
            Flag = [convert]::ToInt16($BinaryVersion.Substring(16,1),2) #The next 1 bit is just a flag that you can ignore.
            Build = [convert]::ToInt16($BinaryVersion.Substring(17,15),2) #The last 15 bits is the build number.
        }
    }
    end{
        Remove-Variable BinaryVersion
        Remove-Variable VersionSizeInBits
    }
}

Function Get-ADExchangeServer{
    <#
        .SYNOPSIS
            Discover all Exchange servers in the current AD domain
        .DESCRIPTION
            Searches the default root configuration naming context for Exchange servers and returns them in a friendly form.
        .OUTPUTS
            Returns an object with 4 properties for each Exchange server:
                FQDN - The Fully Qualified Domain Name of the server
                Roles (Exchange Roles) - Collection of strings returned from ConvertTo-ExchangeRole
                Class - String matching the objectClass AD attribute
                Version - PSCustomObject returned from ConvertTo-ExchangeVersion
        .EXAMPLE
            Get-ADExchangeServer
    #>
    [CmdletBinding()]
    param(
      [Parameter(Mandatory=$true)]
      [String]$ConfigurationNamingContext
    )

    # Import-Module ActiveDirectory -Cmdlet Get-ADObject -Verbose:$false
    [String]$context = $ConfigurationNamingContext
    $Splat = @{
        LDAPFilter = "(|(objectClass=msExchExchangeServer)(objectClass=msExchClientAccessArray))"
        SearchBase = $context
        Properties = 'objectCategory','objectClass','msExchCurrentServerRoles','networkAddress','versionNumber'
    }
    $Results = Get-ADObject @Splat
    ForEach ($ExchServer in $Results) {
        $FQDN = ($ExchServer.networkAddress | Where-Object -FilterScript {$_ -like "ncacn_ip_tcp*"}).Split(":")[1]
        $Roles = ConvertTo-ExchangeRole $ExchServer.msExchCurrentServerRoles
        $Class = $ExchServer.objectClass
        $Category = $ExchServer.objectCategory
        $ExchVersion = ConvertTo-ExchangeVersion -Version $ExchServer.versionNumber

        $Object = New-Object PSObject -Property @{
            FQDN = $FQDN
            Roles = [string]$Roles
            Class = [string]$Class
            Category = $Category
            Version = "$($ExchVersion.MajorVersion).$($ExchVersion.MinorVersion).$($ExchVersion.Build)"
            MajorVersion = $ExchVersion.MajorVersion
            MinorVersion = $ExchVersion.MinorVersion
            # Flag = $ExchVersion.Flag
            Build = $ExchVersion.Build
            # LegacyVersionStructure = $ExchVersion.LegacyVersionStructure
        }
        $Object
    }
}
