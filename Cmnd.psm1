<#
    .EXAMPLE
        $tvs = Get-CmndTv
        $tvs | ConvertTo-Json | Set-Content "cmnd-tvs_$( Get-Date -Format FileDateTime ).json"
        $tvs | Export-Csv -NoTypeInformation -Path "cmnd-tvs_$( Get-Date -Format FileDateTime ).csv"

    .EXAMPLE
        $roomChanges = Get-CmndTvRoomIdChanges
        $roomChanges | Set-CmndTvRoomId

    .EXAMPLE
        $tvInfo = Get-CmndTv | ? PowerStatus -eq 'offline' | Get-CmndTvInfo
        $tvInfo | sort Lastonline | ft -auto Name,Lastonline

    .EXAMPLE
        $tv = Get-CmndTv 'CampTV-RoomA001'
        $checkedInGuest = New-CmndGuest -RoomId $tv.TVRoomId
        Remove-CmndGuest -GuestId $checkedInGuest.guestId
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Add-Type -AssemblyName System.Web


# This will be used to hold the CmndContext object created when Connect-Cmnd is run. This
# allows it to be used by other functions in the module without the user passing it in each time.
$Script:CmndContext = $null

class CmndContext {
    [Uri] $BaseUri
    [Microsoft.PowerShell.Commands.WebRequestSession] $Session
    [String] FullUri([String]$Endpoint) {
        return $this.FullUri($Endpoint, @{})
    }
    [String] FullUri([String]$Endpoint, [Hashtable]$Query) {
        return (Get-UriQuery -Uri ([Uri]::New($this.BaseUri, $Endpoint)) -Query $Query)
    }
}


class IgnoreCertErrorsForTrustedDomains : System.Net.ICertificatePolicy {
    [String[]] $TrustedDomains
    IgnoreCertErrorsForTrustedDomains($TrustedDomains) {
        $this.TrustedDomains = $TrustedDomains
    }
    [bool] CheckValidationResult(
        [System.Net.ServicePoint] $ServicePoint,
        [System.Security.Cryptography.X509Certificates.X509Certificate] $Certificate,
        [System.Net.WebRequest] $WebRequest,
        [int] $PolicyErrors
    ) {
        return $PolicyErrors -eq 0 -or ($WebRequest.RequestUri.Host -in $this.TrustedDomains)
    }
}


function Get-UriQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 1)]
        [Uri]
        $Uri,

        [Parameter(Position = 2)]
        [Hashtable]
        $Query
    )
    process {
        if ($null -eq $Query) {
            $Query = @{}
        }
        $queryBuilder = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        foreach ($key in $Query.Keys) {
            $queryBuilder.Add($key, $Query[$key])
        }
        $uriBuilder = [System.UriBuilder]$Uri
        $uriBuilder.Query = $QueryBuilder.ToString()
        $uriBuilder.ToString()
    }
}


function Get-CmndContext {
    <#
        .SYNOPSIS
            Allows the user to retrieve the CmndContext object created when using Connect-Cmnd
        .EXAMPLE
            $CmndContext = Get-CmndContext
    #>
    [CmdletBinding()]
    [OutputType([CmndContext])]
    param ()
    process {
        if (-not $Script:CmndContext) {
            Write-Error 'Cmnd not found. Try connecting with "Connect-Cmnd" first.'
        }
        return $Script:CmndContext
    }
}


function Connect-Cmnd {
    <#
        .SYNOPSIS
            Sets up the CmndContext object which will save the connection details for other functions.
        .DESCRIPTION
            The returned Cmnd object will also be stored in the module's BhSession variable. This allows
            it to be used by other functions in this module without the user passing it in each time.
        .EXAMPLE
            Connect-Cmnd -DisableCertValidation

            Prompts for credentials interactively using the default URI, and disables cert validation.
        .EXAMPLE
            Connect-Cmnd -BaseUri "https://cmnd.dynamicit.net.au" -Credential $creds

            Connects to a custom URI using saved credentials
   #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    param (
        # REST server base URI.
        [Uri]
        $BaseUri = "https://172.20.44.10:8443",

        [Switch]
        $DisableCertValidation,

        # Leave this blank to prompt interactively
        [PSCredential]
        $Credential
    )

    process {
        if ($DisableCertValidation) {
            [Net.ServicePointManager]::CertificatePolicy = [IgnoreCertErrorsForTrustedDomains]::new($BaseUri.Host)
        }

        try {
            $loginPage = Invoke-WebRequest -UseBasicParsing -Uri $BaseUri
        } catch [System.Net.WebException] {
            throw "Unable to connect to $BaseUri. If there's an SSL error, consider using -DisableCertValidation."
        }

        $executionField = $loginPage.InputFields | Where-Object { $_.Name -eq 'execution' }
        if (-not $executionField -or -not $executionField.Value) {
            throw "Login page for $BaseUri doesn't include an expected input field (name=execution)."
        }

        if (-not $Credential) {
            $Credential = Get-Credential -Message "CMND username and password"
        }

        $context = [CmndContext]@{
            BaseUri = $BaseUri
            Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        }
        $params = @{
            WebSession      = $context.Session
            UseBasicParsing = $true
            Uri             = $context.FullUri("/cas/login")
            Method          = "POST"
            Body            = @{
                username    = $Credential.UserName
                password    = $Credential.GetNetworkCredential().Password
                execution   = $executionField.Value
                _eventId    = "submit"
                geolocation = $null
                submit      = "LOGIN"
            }
        }
        $null = Invoke-WebRequest @params
        # Save the CmndContext for later use by other functions.
        $Script:CmndContext = $context
    }
}


function Invoke-CmndRest {
    [CmdletBinding(DefaultParameterSetName = "Endpoint", SupportsShouldProcess)]
    param(
        # use a custom endpoint
        [Parameter(Mandatory, ParameterSetName = "Endpoint")]
        [String]
        $Endpoint,

        # shortcut to use the IPTV endpoint /SmartInstall/IPTVServlet
        [Parameter(Mandatory, ParameterSetName = "IPTV")]
        [Switch]
        $IPTV,

        # shortcut to use the PMS endpoint /SmartInstall/pms
        [Parameter(Mandatory, ParameterSetName = "PMS")]
        [Switch]
        $PMS,

        # used to construct a query string. e.g. @{type="device"} would be appended to the URI as ?type=device
        [Hashtable]
        $Query,

        # body of the request
        [Hashtable]
        $Body,

        # All known CMND endpoints use POST
        [ValidateSet('GET', 'POST', 'PUT')]
        [String]
        $Method = 'POST'
    )

    begin {
        $context = Get-CmndContext
    }

    process {
        if ($PMS) {
            $Endpoint = "SmartInstall/pms"
        } elseif ($IPTV) {
            $Endpoint = "SmartInstall/IPTVServlet"
        }
        $uri = $context.FullUri($Endpoint, $Query)
        if ($PSCmdlet.ShouldProcess($uri, "$Method $Body")) {
            Invoke-RestMethod -WebSession $context.Session -Method $Method -Uri $Uri -Body $body
        }
    }
}


function Find-CmndTv {
    <#
        .EXAMPLE
            $tvs = Get-CmndTv
            $tvs | ConvertTo-Json | Set-Content "cmnd-tvs_$( Get-Date -Format FileDateTime ).json"
            $tvs | Export-Csv -NoTypeInformation -Path "cmnd-tvs_$( Get-Date -Format FileDateTime ).csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]
        [String]
        $Query,

        [Int]
        $PageSize = 1000
    )

    process {
        $body = @{
            current          = 0
            rowCount         = $PageSize
            "sort[TVRoomID]" = 'asc'
        }
        if ($Query) {
            $body.searchPhrase = $Query
        }
        do {
            $body.current++
            $results = Invoke-CmndRest -Endpoint "SmartInstall/dev" -Query @{ type = "device" } -Body $body
            $results.rows | ForEach-Object {
                if ($_.guestName -and $_.guestName -ne 'None') {
                    $_.guestName = [System.Net.WebUtility]::HtmlDecode($_.guestName)
                }
                $_
            }
        } until ($results.rows.Count -eq 0 -or ($results.current * $results.rowCount) -ge $results.total)
    }
}


function Get-CmndTv {
    <#
        .EXAMPLE
            $tvs = Get-CmndTv
            $tvs | ConvertTo-Json | Set-Content "cmnd-tvs_$( Get-Date -Format FileDateTime ).json"
            $tvs | Export-Csv -NoTypeInformation -Path "cmnd-tvs_$( Get-Date -Format FileDateTime ).csv"
    #>
    [CmdletBinding(DefaultParameterSetName = "All")]
    param(
        [Parameter(Mandatory, ParameterSetName = "Name", ValueFromPipelineByPropertyName)]
        [Alias('TVName')]
        [String]
        $Name,

        [Parameter(Mandatory, ParameterSetName = "Serial", ValueFromPipelineByPropertyName)]
        [Alias('TVSerialNumber')]
        [ValidateLength(14, 14)]
        [String]
        $SerialNumber,

        [Parameter(Mandatory, ParameterSetName = "ID", ValueFromPipelineByPropertyName)]
        [Alias('TVID')]
        [ValidateLength(26, 26)]
        [String]
        $ID
    )
    process {
        if ($ID) {
            $query = $ID.Substring(0, $ID.Length - 14)
        } elseif ($SerialNumber) {
            $query = $SerialNumber
        } elseif ($Name) {
            $query = $Name
        } else {
            $query = $null
        }
        $results = Find-CmndTv -Query $query
        if ($ID) {
            $results | Where-Object Id -eq $ID
        } elseif ($SerialNumber) {
            $results | Where-Object TVSerialNumber -eq $SerialNumber
        } elseif ($Name) {
            $results | Where-Object TVName -eq $Name
        } else {
            $results
        }
    }
}


function Get-CmndTvInfo {
    <#
        .EXAMPLE
            $tvInfo = Get-CmndTv | ? PowerStatus -eq 'offline' | Get-CmndTvInfo
            $tvInfo | sort Lastonline | ft -auto Name,Lastonline
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias("TvId")]
        [String]
        $Id,

        # don't clean up the results from CMND.
        [Alias('TVName')]
        [Switch]
        $RawData
    )
    begin {
        $spanTagFields = @(
            'AndroidAppsData', 'Banner', 'CustomDashboardFallback', 'HTVCfg.xml', 'MainFirmware', 'MediaChannels',
            'ProfessionalApps', 'Schedules', 'Script', 'SmartInfoShow', 'SmartInfoPages', 'ProfessionalAppsData',
            'RoomSpecificSettings', 'TVChannelList', 'TVSettings', 'MyChoice', 'AndroidApps'
        )
        $dateFields = @(
            'ProfessionalAppsData', 'RoomSpecificSettings', 'TVChannelList', 'TVSettings',
            'MyChoice', 'AndroidApps', 'Lastonline'
        )
        $dateRegex = '([\d/]{10})[:-](\d\d:\d\d(?::\d\d)?)'
    }
    process {
        $body = @{
            mode = "info"
            id   = $Id
        }
        $response = Invoke-CmndRest -IPTV -Body $body
        if (-not $RawData) {
            foreach ($field in $spanTagFields) {
                $response.$field = ($response.$field -replace '</?span[^>]*>').Trim()
            }
            foreach ($field in $dateFields) {
                $dateString = $response.$field
                $date = $null
                if ($dateString -eq '00/00/0000:--:--') {
                    $date = $null
                } elseif ($dateString) {
                    $dateString = $dateString -replace $dateRegex, '$1 $2'
                    try {
                        $date = Get-Date $dateString
                    } catch {
                        # sometimes the timestamp is invalid, in this case we'll try process just the date.
                        $date = Get-Date $dateString.Substring(0, 10)
                    }
                }
                $response.$field = $date
            }
        }
        $response
    }
}


function Invoke-CmndWakeOnLan {
    <#
        .EXAMPLE
            Invoke-CmndWakeOnLan -Id XM1A222900426670AF24AFB8C1
        .EXAMPLE
            Invoke-CmndWakeOnLan | Where-Object status -eq 'fail'
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [Alias("TvId")]
        [String[]]
        $Id
    )
    begin {
        $ids = [System.Collections.Generic.List[Object]]@()
    }
    process {
        if (-not $Id) {
            $Id = Get-CmndTv | Where-Object PowerStatus -eq 'offline' | Select-Object -ExpandProperty id
        }
        $Id | ForEach-Object { $ids.Add($_) }
    }

    end {
        $total = $ids.Count
        Write-Information "Waking $total TVs"
        $count = 0
        $ids | ForEach-Object {
            $count++
            if ($total -gt 1) {
                $status = "{0}/{1}: {2}" -f $count, $total, $_
                Write-Progress -Activity "Waking TV" -Status $status -PercentComplete ($count / $total * 100)
            }
            $body = @{
                mode  = "power"
                id    = $_
                type  = "tv"
                power = "OFFLINE"
            }
            $response = Invoke-CmndRest -IPTV -Body $body
            [PSCustomObject]@{
                Id     = $_
                Status = $response.status
                Reason = if ($response.PSObject.Properties.Name -contains "reason") { $response.reason } else { $null }
            }
        }
    }
}


function Rename-CmndTv {
    <#
        .EXAMPLE
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias("TvId")]
        [String]
        $Id,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('TVName')]
        [string]
        $NewName
    )
    process {
        $body = @{
            mode = "mainText"
            id   = $Id
            name = $NewName
        }
        $response = Invoke-CmndRest -IPTV -Body $body
        [PSCustomObject]@{
            Id      = $Id
            NewName = $NewName
            Status  = $response.status
            Reason  = if ($response.PSObject.Properties.Name -contains "reason") { $response.reason } else { $null }
        }
    }
}


function Set-CmndTvRoomId {
    <#
        .EXAMPLE
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias("TvId")]
        [String]
        $Id,
        [Parameter(ValueFromPipelineByPropertyName)]

        [Alias('RoomId')]
        [ValidatePattern('^\d{1,5}$')]
        [String]
        $NewRoomId
    )

    process {
        $body = @{
            type   = "changeRoomID"
            tvID   = $Id
            roomID = $NewRoomId
        }
        $response = Invoke-CmndRest -PMS -Body $body
        [PSCustomObject]@{
            Id        = $Id
            NewRoomId = $NewRoomId
            Status    = $response.status
            Reason    = if ($response.PSObject.Properties.Name -contains "reason") { $response.reason } else { $null }
        }
    }
}


function ConvertTo-CmndTvRoomId {
    <#
        .EXAMPLE
            Get-CmndTv | ConvertTo-CmndTvRoomId | Set-CmndTvRoomId
    #>
    param (
        # TV Name to extract room ID from
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        $TVName,

        # Regex to extract the room detals. It must contain a named capture group called "room" and can
        # optionally include a group called "block". If the block matches an alpha character, it will be
        # converted into a number and added as a prefix to the room number.
        [ValidateNotNullOrEmpty()]
        [Regex]
        $Match = "Room(?<block>[A-G])(?<room>\d\d\d)" # e.g. RoomB077 -> 20077
    )

    begin {
        $note = 'Regex must contain capture group "room" and can optionally include a group called "block"'
        $unexpectedGroups = $Match.GetGroupNames() | Where-Object { $_ -notin 0, 'room', 'block' }
        if ($unexpectedGroups) {
            Write-Error "Found unexpected capture group(s) in Match regex: $( $unexpectedGroups -join ', ' ). $note"
        } elseif ($Match.GetGroupNames() -notcontains 'room') {
            Write-Error "Unable to find named capture group called 'room'. $note"
        }
    }
    process {
        if ($TVName -match $Match) {
            $prefix = ""
            if ($Match.GetGroupNames() -contains 'block') {
                $blockNumber = [int]([char]$Matches['block'].ToUpper()) - 64
                $prefix = [String]$blockNumber
            }
            $roomId = $Matches['room']
            if (($roomId.Length + $prefix.Length) -gt 5) {
                Write-Error 'RoomId will exceed the maximum characters (5) available.'
            }
            if ($prefix) {
                $padding = 5 - $prefix.Length
                $roomId = $prefix + $roomId.PadLeft($padding, '0')
            }
            $roomId
        }
    }
}


function Get-CmndTvRoomIdChanges {
    <#
        .EXAMPLE
            Get-CmndTvRoomIdChanges | Set-CmndTvRoomId
    #>
    param (
        # TV object. If not provided, all TVs will be checked.
        [Parameter(ValueFromPipeline)]
        [Object[]]
        $TV,

        # Regex to extract the room detals. It must contain a named capture group called "room" and can
        # optionally include a group called "block". If the block matches an alpha character, it will be
        # converted into a number and added as a prefix to the room number.
        [Regex]
        $Match = "Room(?<block>[A-G])(?<room>\d\d\d)" # e.g. RoomB077 -> 20077
    )
    process {
        if (-not $TV) {
            $TV = Get-CmndTv
        }
        $TV | ForEach-Object {
            $roomId = ConvertTo-CmndTvRoomId -TVName $_.TVName -Match $Match
            if ($roomId -and $roomId -ne $_.TVRoomID) {
                [PSCustomObject]@{
                    Id        = $_.Id
                    TVName    = $_.TVName
                    OldRoomId = $_.TVRoomID
                    NewRoomId = $roomId
                }
            }
        }
    }
}


function SetGuestState {
    <#
        .SYNOPSIS
            Used by other functions to check in/out guests from rooms.
        .DESCRIPTION
            Used by other functions to check in/out guests from rooms.
            Not exposed as a standalone function as the behaviour is odd, and it's
            better wrapped with other functions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [String]
        $GuestId,

        [Parameter(Mandatory)]
        [ValidateSet('CheckedIn', 'CheckedOut')]
        [String]
        $State
    )
    if ($State -eq 'CheckedOut') {
        $checkedOut = 'true'
    } else {
        $checkedOut = 'false'
    }
    if ($PSCmdlet.ShouldProcess($GuestId, "Applying: $State")) {
        $results = Invoke-CmndRest -PMS -Body @{
            type    = 'switchCheckStatus'
            id      = $GuestId
            checkin = $checkedOut # this is the current state, not the desired state.
        }
        if ($results.status -ne 'success') {
            Write-Error (ConvertTo-Json -Compress $results)
        } elseif ('data' -in $results.PSObject.Properties.Name) {
            $results.data
        } else {
            $results
        }
    }
}


function New-CmndGuest {
    <#
        .SYNOPSIS
            Creates a new guest and checks it in to a room.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\d{1,5}$')]
        [String]
        $RoomId,

        [Parameter(Mandatory)]
        [String]
        $GuestName
    )
    process {
        if ($PSCmdlet.ShouldProcess($RoomId, "Adding $GuestName to room")) {
            $results = Invoke-CmndRest -PMS -Body @{
                type   = 'renameGuestname'
                id     = 'None'
                name   = $GuestName
                roomid = $RoomId
            }
            if ($results.status -ne 'success') {
                Write-Error (ConvertTo-Json -Compress $results)
            } elseif ('guestId' -notin $results.data.PSObject.Properties.Name) {
                Write-Error "No guestId found: $( ConvertTo-Json -Compress $results )"
            } else {
                SetGuestState -GuestId $results.data.guestId -State CheckedIn
            }
        }
    }
}


function Remove-CmndGuest {
    <#
        .SYNOPSIS
            Removes a guest from a room
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [String]
        $GuestId
    )
    process {
        if ($PSCmdlet.ShouldProcess($GuestId, "Removing guest")) {
            $out = SetGuestState -GuestId $GuestId -State CheckedOut
            $properties = $out.PSObject.Properties.Name
            if ('status' -in $properties) {
                if ($out.status -ne 'success') {
                    $out
                }
            } elseif ('checkin' -in $properties -and $out.checkin -eq 'N') {
                $null = SetGuestState -GuestId $GuestId -State CheckedIn
                $out = SetGuestState -GuestId $GuestId -State CheckedOut
            }
        }
    }
}


function Get-CmndTvApp {
    <#
        .SYNOPSIS
            Gets a list of apps/sources installed and available on a TV
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias("TvId")]
        [String]
        $Id
    )
    process {
        $response = Invoke-CmndRest -Endpoint "SmartInstall/remote" -Body @{
            method      = "request"
            settingName = "ApplicationList"
            tvid        = $Id
        }

        if ($response.status -ne 'success') {
            Write-Error (ConvertTo-Json -Compress $response)
        } else {
            $response.data | ForEach-Object {
                [PSCustomObject]@{
                    TvID        = $Id
                    Application = $_
                }
            }
        }
    }
}


Export-ModuleMember -Function Get-CmndContext
Export-ModuleMember -Function Connect-Cmnd
Export-ModuleMember -Function Invoke-CmndRest
Export-ModuleMember -Function Find-CmndTv
Export-ModuleMember -Function Get-CmndTv
Export-ModuleMember -Function Get-CmndTvInfo
Export-ModuleMember -Function Rename-CmndTv
Export-ModuleMember -Function Invoke-CmndWakeOnLan
Export-ModuleMember -Function ConvertTo-CmndTvRoomId
Export-ModuleMember -Function Set-CmndTvRoomId
Export-ModuleMember -Function Get-CmndTvRoomIdChanges
Export-ModuleMember -Function New-CmndGuest
Export-ModuleMember -Function Remove-CmndGuest
Export-ModuleMember -Function Get-CmndTvApp

# SIG # Begin signature block
# MIIm3wYJKoZIhvcNAQcCoIIm0DCCJswCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPL94TtLKQyEC4sG0lC4wS726
# xBOggh/wMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGGjCCBAKgAwIBAgIQYh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG
# 9w0BAQwFADBWMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS0wKwYDVQQDEyRTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYw
# HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBUMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIB
# igKCAYEAmyudU/o1P45gBkNqwM/1f/bIU1MYyM7TbH78WAeVF3llMwsRHgBGRmxD
# eEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk
# 9vT0k2oWJMJjL9G//N523hAm4jF4UjrW2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7Xw
# iunD7mBxNtecM6ytIdUlh08T2z7mJEXZD9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ
# 0arWZVeffvMr/iiIROSCzKoDmWABDRzV/UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZX
# nYvZQgWx/SXiJDRSAolRzZEZquE6cbcH747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+t
# AfiWu01TPhCr9VrkxsHC5qFNxaThTG5j4/Kc+ODD2dX/fmBECELcvzUHf9shoFvr
# n35XGf2RPaNTO2uSZ6n9otv7jElspkfK9qEATHZcodp+R4q2OIypxR//YEb3fkDn
# 3UayWW9bAgMBAAGjggFkMIIBYDAfBgNVHSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaR
# XBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxvSK4rVKYpqhekzQwwDgYDVR0PAQH/BAQD
# AgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYD
# VR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEEATBLBgNVHR8ERDBCMECgPqA8hjpodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RS
# NDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LnA3YzAj
# BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEM
# BQADggIBAAb/guF3YzZue6EVIJsT/wT+mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXK
# ZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFyAQ9GXTmlk7MjcgQbDCx6mn7yIawsppWk
# vfPkKaAQsiqaT9DnMWBHVNIabGqgQSGTrQWo43MOfsPynhbz2Hyxf5XWKZpRvr3d
# MapandPfYgoZ8iDL2OR3sYztgJrbG6VZ9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwF
# kvjFV3jS49ZSc4lShKK6BrPTJYs4NG1DGzmpToTnwoqZ8fAmi2XlZnuchC4NPSZa
# PATHvNIzt+z1PHo35D/f7j2pO1S8BCysQDHCbM5Mnomnq5aYcKCsdbh0czchOm8b
# kinLrYrKpii+Tk7pwL7TjRKLXkomm5D1Umds++pip8wH2cQpf93at3VDcOK4N7Ew
# oIJB0kak6pSzEu4I64U6gZs7tS/dGNSljf2OSSnRr7KWzq03zl8l75jy+hOds9TW
# SenLbjBQUGR96cFr6lEUfAIEHVC1L68Y1GGxx4/eRI82ut83axHMViw1+sVpbPxg
# 51Tbnio1lB93079WPFnYaOvfGAA0e0zcfF/M9gXr+korwQTh2Prqooq2bYNMvUoU
# KD85gnJ+t0smrWrb8dee2CvYZXD5laGtaAxOfy/VKNmwuWuAh9kcMIIGcjCCBNqg
# AwIBAgIRAPtBIGjFrPxEQO4Ox6/zH6owDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yMjA5MjEwMDAwMDBaFw0y
# NTA5MjAyMzU5NTlaMGMxCzAJBgNVBAYTAkFVMRowGAYDVQQIDBFXZXN0ZXJuIEF1
# c3RyYWxpYTEbMBkGA1UECgwSRHluYW1pYyBJVCBQVFkgTFREMRswGQYDVQQDDBJE
# eW5hbWljIElUIFBUWSBMVEQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC+zpX5dNIMBTKm4r6ivibucKGet/fh/75vFbG9OY/erV1cqM9bP9GnMk6WDWEk
# gtqZ6N2jrx47B+cqhROgn4qu4sC3d/AUQei9z7XUne8jlu9FPIVlRlmfTmu4GC1V
# n1AX4PB3NMb9uj4NbL5OT5D2aWo9q0ypnRMsRWjYWdQkPUP4j9k/PEQEsliOqgKG
# vgq3uiejTcUQD3+igk8i7lDUDNE8v69wR6zMmVo+BsO55lweduCXmsa3HKSOKP8X
# j67EtU83hVOBxjLFsaILR/oMXTo2GbGDpcRqRbkf5FxhLkZNJxbLVPglQCtyjVto
# uKeFZS8frdtQ63w3Y9UCUrD7rwoAa4kV4S2iMDcrajncwPXzu/GAGTR8B58Oy179
# QPIg/HyKnsBUD3oxfYOxkTsWr8+atZQ39MFv8V+D08YzIc0tDvM4CFkqmgWIrGJ+
# ez2sJLIqVAqyjxK6VvTuE/uOe1nRRAUtx/eG6LccjAS53mgH7JPWDXhHEjFkfut9
# vlKgairOJU6AvI5wY8MLC/adFYPwP3STl8bEPTvodJ48JF8cNBJay1nYhIDqv0+P
# V18sLw7vqADNWWR/mjTWJ9vBhisNmrD1L0qW8dBc5zxdSCsJ5NDrll23aPFDrcaG
# 8NvxeMjVNEtIH5lOqvCAWkU5alr2QOQlDYouvxnZWLlL5wIDAQABo4IBrjCCAaow
# HwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhekzQwwHQYDVR0OBBYEFLRIF51V
# FzpR6eJoz1FLLap3iYqjMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUw
# IwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBJ
# BgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5BggrBgEFBQcBAQRtMGswRAYIKwYB
# BQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVT
# aWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv
# LmNvbTAjBgNVHREEHDAagRhzdXBwb3J0QGR5bmFtaWNpdC5uZXQuYXUwDQYJKoZI
# hvcNAQEMBQADggGBAAkTwJ6A8z2pzWlFbAq3S4Z/2xxJ8Q9YUrGnj1/uD0DNGmif
# LbjpkboZydH7een9rJLYSP/9FthgVpBOTHSmFLFPte4tA90FKO+FlhqTpFfIJT7B
# jnsa6hI3pVYQmQn2IE8qHKTCtqWSBRjZ0tfScI2CJzoRXOYWEwVXdrsxtZsZlgal
# 8Y74yfw1wXDmoIhNjfkvkpNnGP6XVu369au2nmAgQ6K2/VYdXBsf747iXWUHBaAG
# vtx55Y4oIu/tkWMpSfZRRMWpeSlqnk2aWhseGvDgSXqqsym6sC1KGKdF1OILjJ+5
# U02KtK5MhVgBE0byr9/jKYyaCM2NbqZ8yM98Wqo1qioHGBNrVKnbZZUhaZXFBIO/
# 73n3UyeiWmW0EyvhlLWZC5qGIOt4MRJF7x2Kcnx34HHWn8mG2WsRw2l7vrF/h/q1
# 3Fi3TDcxKmtO7sUjvAkjIPyhbEyT/ZyLR7/TT1To+jGOXW6p+slUKHKcGNNSM4xO
# 0PnCx1+s23Qu7m4oFTCCBuwwggTUoAMCAQICEDAPb6zdZph0fKlGNqd4LbkwDQYJ
# KoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
# MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
# ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
# aG9yaXR5MB4XDTE5MDUwMjAwMDAwMFoXDTM4MDExODIzNTk1OVowfTELMAkGA1UE
# BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2Fs
# Zm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdv
# IFJTQSBUaW1lIFN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAyBsBr9ksfoiZfQGYPyCQvZyAIVSTuc+gPlPvs1rAdtYaBKXOR4O168TM
# STTL80VlufmnZBYmCfvVMlJ5LsljwhObtoY/AQWSZm8hq9VxEHmH9EYqzcRaydvX
# XUlNclYP3MnjU5g6Kh78zlhJ07/zObu5pCNCrNAVw3+eolzXOPEWsnDTo8Tfs8Vy
# rC4Kd/wNlFK3/B+VcyQ9ASi8Dw1Ps5EBjm6dJ3VV0Rc7NCF7lwGUr3+Az9ERCleE
# yX9W4L1GnIK+lJ2/tCCwYH64TfUNP9vQ6oWMilZx0S2UTMiMPNMUopy9Jv/TUyDH
# YGmbWApU9AXn/TGs+ciFF8e4KRmkKS9G493bkV+fPzY+DjBnK0a3Na+WvtpMYMyo
# u58NFNQYxDCYdIIhz2JWtSFzEh79qsoIWId3pBXrGVX/0DlULSbuRRo6b83XhPDX
# 8CjFT2SDAtT74t7xvAIo9G3aJ4oG0paH3uhrDvBbfel2aZMgHEqXLHcZK5OVmJyX
# nuuOwXhWxkQl3wYSmgYtnwNe/YOiU2fKsfqNoWTJiJJZy6hGwMnypv99V9sSdvqK
# QSTUG/xypRSi1K1DHKRJi0E5FAMeKfobpSKupcNNgtCN2mu32/cYQFdz8HGj+0p9
# RTbB942C+rnJDVOAffq2OVgy728YUInXT50zvRq1naHelUF6p4MCAwEAAaOCAVow
# ggFWMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBQa
# ofhhGSAPw0F3RSiO0TVfBhIEVTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgw
# BgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAw
# UAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJU
# cnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYGCCsGAQUFBwEBBGow
# aDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1VTRVJUcnVz
# dFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2Vy
# dHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBtVIGlM10W4bVTgZF13wN6Mgst
# JYQRsrDbKn0qBfW8Oyf0WqC5SVmQKWxhy7VQ2+J9+Z8A70DDrdPi5Fb5WEHP8ULl
# EH3/sHQfj8ZcCfkzXuqgHCZYXPO0EQ/V1cPivNVYeL9IduFEZ22PsEMQD43k+Thi
# vxMBxYWjTMXMslMwlaTW9JZWCLjNXH8Blr5yUmo7Qjd8Fng5k5OUm7Hcsm1BbWfN
# yW+QPX9FcsEbI9bCVYRm5LPFZgb289ZLXq2jK0KKIZL+qG9aJXBigXNjXqC72NzX
# StM9r4MGOBIdJIct5PwC1j53BLwENrXnd8ucLo0jGLmjwkcd8F3WoXNXBWiap8k3
# ZR2+6rzYQoNDBaWLpgn/0aGUpk6qPQn1BWy30mRa2Coiwkud8TleTN5IPZs0lpoJ
# X47997FSkc4/ifYcobWpdR9xv1tDXWU9UIFuq/DQ0/yysx+2mZYm9Dx5i1xkzM3u
# J5rloMAMcofBbk1a0x7q8ETmMm8c6xdOlMN4ZSA7D0GqH+mhQZ3+sbigZSo04N6o
# +TzmwTC7wKBjLPxcFgCo0MR/6hGdHgbGpm0yXbQ4CStJB6r97DDa8acvz7f9+tCj
# hNknnvsBZne5VhDhIG7GrrH5trrINV0zdo7xfCAMKneutaIChrop7rRaALGMq+P5
# CslUXdS5anSevUiumDCCBvUwggTdoAMCAQICEDlMJeF8oG0nqGXiO9kdItQwDQYJ
# KoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFu
# Y2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIz
# MDUwMzAwMDAwMFoXDTM0MDgwMjIzNTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNV
# BAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UE
# AwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQCkkyhSS88nh3akKRyZOMDnDtTRHOxoywFk
# 5IrNd7BxZYK8n/yLu7uVmPslEY5aiAlmERRYsroiW+b2MvFdLcB6og7g4FZk7aHl
# gSByIGRBbMfDCPrzfV3vIZrCftcsw7oRmB780yAIQrNfv3+IWDKrMLPYjHqWShkT
# XKz856vpHBYusLA4lUrPhVCrZwMlobs46Q9vqVqakSgTNbkf8z3hJMhrsZnoDe+7
# TeU9jFQDkdD8Lc9VMzh6CRwH0SLgY4anvv3Sg3MSFJuaTAlGvTS84UtQe3LgW/0Z
# ux88ahl7brstRCq+PEzMrIoEk8ZXhqBzNiuBl/obm36Ih9hSeYn+bnc317tQn/oY
# JU8T8l58qbEgWimro0KHd+D0TAJI3VilU6ajoO0ZlmUVKcXtMzAl5paDgZr2YGaQ
# WAeAzUJ1rPu0kdDF3QFAaraoEO72jXq3nnWv06VLGKEMn1ewXiVHkXTNdRLRnG/k
# Xg2b7HUm7v7T9ZIvUoXo2kRRKqLMAMqHZkOjGwDvorWWnWKtJwvyG0rJw5RCN4gg
# hKiHrsO6I3J7+FTv+GsnsIX1p0OF2Cs5dNtadwLRpPr1zZw9zB+uUdB7bNgdLRFC
# U3F0wuU1qi1SEtklz/DT0JFDEtcyfZhs43dByP8fJFTvbq3GPlV78VyHOmTxYEsF
# T++5L+wJEwIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1
# XwYSBFUwHQYDVR0OBBYEFAMPMciRKpO9Y/PRXU2kNA/SlQEYMA4GA1UdDwEB/wQE
# AwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1Ud
# IARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
# dGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8v
# Y3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYI
# KwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29t
# L1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6
# Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBMm2VY+uB5z+8V
# wzJt3jOR63dY4uu9y0o8dd5+lG3DIscEld9laWETDPYMnvWJIF7Bh8cDJMrHpfAm
# 3/j4MWUN4OttUVemjIRSCEYcKsLe8tqKRfO+9/YuxH7t+O1ov3pWSOlh5Zo5d7y+
# upFkiHX/XYUWNCfSKcv/7S3a/76TDOxtog3Mw/FuvSGRGiMAUq2X1GJ4KoR5qNc9
# rCGPcMMkeTqX8Q2jo1tT2KsAulj7NYBPXyhxbBlewoNykK7gxtjymfvqtJJlfAd8
# NUQdrVgYa2L73mzECqls0yFGcNwvjXVMI8JB0HqWO8NL3c2SJnR2XDegmiSeTl9O
# 048P5RNPWURlS0Nkz0j4Z2e5Tb/MDbE6MNChPUitemXk7N/gAfCzKko5rMGk+al9
# NdAyQKCxGSoYIbLIfQVxGksnNqrgmByDdefHfkuEQ81D+5CXdioSrEDBcFuZCkD6
# gG2UYXvIbrnIZ2ckXFCNASDeB/cB1PguEc2dg+X4yiUcRD0n5bCGRyoLG4R2fXto
# T4239xO07aAt7nMP2RC6nZksfNd1H48QxJTmfiTllUqIjCfWhWYd+a5kdpHoSP7I
# VQrtKcMf3jimwBT7Mj34qYNiNsjDvgCHHKv6SkIciQPc9Vx8cNldeE7un14g5glq
# fCsIo0j1FfwET9/NIRx65fWOGtS5QDGCBlkwggZVAgEBMGkwVDELMAkGA1UEBhMC
# R0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQ
# dWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNgIRAPtBIGjFrPxEQO4Ox6/zH6owCQYF
# Kw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJ
# KoZIhvcNAQkEMRYEFCWKVAYeQxH+VOTRSCJmYO5GUjLlMA0GCSqGSIb3DQEBAQUA
# BIICAErLCMbPA0UjUy54J6pnty48tuQtrZeWUg4Bty3HI7B5tz6xFXS/zPBZcJSD
# 47b5kOpYOoVeBajJ0XJsCJjadKY5ESkvYs0OjDmucWD70AredNxRMYmAzqe80L0A
# EG9S0z8AWwQOKpGOJoapdfKxu1P45D98RHcPlaJp6BQPLHGHPemmEb2u0H6ryR5o
# VMi0NiBbRMf6dxuoBZWazEmicF3f9O5HaZu6TP06OCx1gCLCLfypsqqQMW0qa3EU
# yg3VUz2lw+xblZj7m5dxoKOqX5UC12cnegn535g9IguxHnsHL0UZEhepwpUr8wYX
# LxBZ8bJloN8dV+V26wCmvfv5+X4bKN7SyXJeLi7h+ukXS1r/FI5lBjo2apQghRhH
# 0rcfGTxNguOmS/iniP7ZRn2diZeGyqMkkIRXTuS1U+JRNDtQ09HDpa7COINnOnMm
# AQeUQVDfmNvCzCi8LwijqOGfOgVL+qxdDsRM3Tija82xg8I5bV1mDfWq3DVC71iM
# matobGUZbzsrnVduJqhtSU2LT6GEOJTAYp/Y5TmNaMo8AHqN4b1tEEFrMOnT81UD
# YW0RUNM0dToWq/JfvsO2p36bQXwfMzNSYWZkoOdU5PhKZoLsbPhBQXXwqzyuvBH1
# Oy7UWmrIIc8d2U5w6QH+eZ/rosSid3H1RzWxZAmOgRE9yTeboYIDSzCCA0cGCSqG
# SIb3DQEJBjGCAzgwggM0AgEBMIGRMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJH
# cmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGlu
# ZyBDQQIQOUwl4XygbSeoZeI72R0i1DANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMTEyNDA0NDgxMVow
# PwYJKoZIhvcNAQkEMTIEMKZFwbQ8e7iEHahafJj45+M9LFYag0OzF8Tbn0uvOx2h
# fhyfeB1A3y6JzZ9YUAsqVTANBgkqhkiG9w0BAQEFAASCAgCXCEil1X9Jx47hqmqU
# qgQ39D51H8dH3EGadivnFG6g9WBW/NwtGQT0TWK3w0RCbjd8YK6iNHgiJ1cbU8i2
# UvmTkMHbuINCniprxOYg6iwLF6z9RQid29ASHy0bzgLLrb1fByo1srrrmMkzPW20
# DyD9aFXAy6lcrVxeBzKu1yVMbjWe7ALLLHj2FXw8DWO/8lMKglY1ld2T6sv2JByy
# WCtT0DpDg723+RUZLDsIFokRyDwwe9v0vkFEF7ytuxMWD2Nt0LFynORh0QvzoVRq
# +6zvYyd/rXsXL2HcfhaxLQ73BHUsLt72x+4kA53p9/LnNxo9UdF/u1zD+ojz+nvm
# u6NyrHrJgCDLGj5Yc7WcT4Bdyu5pVmrb76P3c0ZWvNWfapDCXF0WOLT8GSyXIvQm
# yJklP28YF4E/VVv9dCr4N+aBoPyqRMLE8OrcAK9Bwabgk9ViQLZWfGLb2TaLsyJb
# +gQE5vnGSGSSrN0orrWvsKTDRZaMxfmv4f+XePRsPOsywaD0qoNXywEICX0CjHvH
# EOEm1M37IGEzog1oa80yzhjzmv3ExC7UOEmIcxirw8xY6AW3hPwUyr8l3va1zXci
# BsZsXo3lAvDSeQdtMFUbRxbzSli5k/nN3Z1hP443w0aoBkJbBc9ZgIztLwos5MG/
# dAIycf7WfQZhpBuaGADTBIHi1g==
# SIG # End signature block
