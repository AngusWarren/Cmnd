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


function Get-CmndFile {
    <#
        .EXAMPLE
            $channelFiles = Get-CmndFile -Type ChannelPackageData
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory)]
        [ValidateSet(
            'CloneData','Firmware','SettingPackageData','ChannelPackageData','AppPackageList',
            'BannersList','WelcomeList','UiCustomizations','ScheduleList'
        )]
        [String]
        $Type,

        [Int]
        $PageSize = 1000
    )

    process {
        $query = @{
            type = "get$Type"
        }
        $body = @{
            current          = 0
            rowCount         = $PageSize
            "sort[id]" = 'asc'
        }
        do {
            $body.current++
            $results = Invoke-CmndRest -Endpoint "SmartInstall/getFile" -Query $query -Method POST -Body $body
            if ($results -is [String]) {
                # getFirmware has 'platform' and 'platForm' keys. PowerShell is case insensitive and can't handle this.
                $results = ConvertFrom-Json -InputObject ($results -creplace '"platForm":','"platForm2":')
            }
            $results.rows
        } until ($results.rows.Count -eq 0 -or ($results.current * $results.rowCount) -ge $results.total)
    }
}


function Get-CmndFileChannelMap {
    <#
        .EXAMPLE
            $files = Get-CmndFile -Type ChannelPackageData
            $channels = $files[-1] | Get-CmndFileChannelMap
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="Get-CmndFile")]
        [String]
        $Value,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="Get-CmndFile")]
        [Parameter(Mandatory, ParameterSetName="FileId")]
        [Alias('Id')]
        [Int]
        $FileId
    )

    process {
        if ($PsCmdlet.ParameterSetName -eq 'FileId') {
            $matchingFile = Get-CmndFile -Type ChannelPackageData | Where-Object Id -eq $FileId
            $Value = $matchingFile.value
        }
        $parsedValue = ConvertFrom-Json -InputObject ([System.Net.WebUtility]::HtmlDecode($Value))
        $channels = $parsedValue.v5Channel.channelMap.channel
        foreach ($channel in $channels) {
            $type = @($channel.PSObject.Properties.Name) -ne 'setup' | Select-Object -First 1
            $data = $channel.$type
            if ($type -eq 'source') {
                $source = $data.type
            } elseif ($type -in 'multicast','unicast','media') {
                $source = $data.url
            } elseif ($type -eq 'broadcast') {
                $source = $data.frequency
            } elseif ($type -eq 'app') {
                $source = $data.appName
            } else {
                $source = $null
            }
            [PSCustomObject]@{
                Name = $channel.setup.name
                Number = $channel.setup.presetnumber
                Type = $type
                Source = $source
                Data = $data
                Setup = $channel.setup
                FileId = $FileId
            }
        }
    }
}


function ConvertTo-M3u {
    <#
        .EXAMPLE
            Get-CmndFileChannelMap -Id 1 | ConvertTo-M3u
        .EXAMPLE
            $newestFile = Get-CmndFile -Type ChannelPackageData | Select-Object -Last 1
            $newestFile | Get-CmndFileChannelMap | ConvertTo-M3u
        .EXAMPLE
            $httpRoot = "C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT"
            Get-CmndFileChannelMap -Id 1 | ConvertTo-M3u | Set-Content "$httpRoot\iptv.m3u"

            This will make the file available at http://<cmnd_server>:8080/iptv.m3u
    #>
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        $Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        $Number,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        $Type,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        $Source
    )

    begin {
        $channels = [Collections.Generic.List[Hashtable]]::New()
        $invalidM3uCharacterRegex = '[#"]'
    }
    process {

        if ($Type -in 'multicast', 'unicast', 'media') {
            $uri = [Uri]$Source
            if ($uri.Scheme -in 'multicast','unicast') {
                # CMND uses a non-standard URL structure for RTP streams. We replace it with rtp:// and strip the path.
                # example: "unicast://192.168.1.1:5777/0/0/0/VBR" -> "rtp://192.168.1.1:5777"
                # TODO: Should we convert the path into onid, tsid, sid as query params?
                $Source = "rtp://$( $uri.Host ):$( $uri.Port )"
            }
            $channels.Add(@{
                Name = $Name -replace $invalidM3uCharacterRegex
                Number = $Number -replace $invalidM3uCharacterRegex
                Url = $Source
            })
        }
    }
    end {
        $lines = @('#EXTM3U')
        $lines += foreach ($channel in $channels) {
            '#EXTINF:0 tvg-name="{0}" tvg-id="{1}",{0}' -f $channel.Name, $channel.Number
            $channel.Url
        }
        $lines -replace '^\s+' -join "`n"
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
Export-ModuleMember -Function Get-CmndFile
Export-ModuleMember -Function Get-CmndFileChannelMap
Export-ModuleMember -Function ConvertTo-M3u
