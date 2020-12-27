<#
.SYNOPSIS
    Run a Thycotic Secret Server Discovery or ComputerScan

.DESCRIPTION
    Call the Thycotic Secret Server REST API /Discovery/status endpoint to
    check whether a Discovery or ComputerScan is already running and if not,
    start it by calling the /Discovery/run endpoint.


Copyright 2020, The Migus Group, LLC. All rights reserved
#>

[CmdletBinding(DefaultParameterSetName = 'UserPass')]
Param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("ComputerScan", "Discovery")][string]$CommandType = "Discovery",
    [Parameter(Mandatory = $true, Position = 1)]
    [Uri]$SecretServerUri,
    [Parameter(Mandatory = $true, ParameterSetName = "UserPass", Position = 2)]
    [string]$Username,
    [Parameter(Mandatory = $true, ParameterSetName = "UserPass", Position = 3)]
    [SecureString]$Password,
    [Parameter(Mandatory = $true, ParameterSetName = "Credential", Position = 2)]
    [PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

$BaseUri = ${SecretServerUri}.ToString().TrimEnd('/')
Write-Debug "BaseUri: ${BaseUri}"

if ($Credential) {
    Write-Debug "Dereferencing Username and Password from $Credential"
    $Username = $Credential.Username
    $Password = $Credential.Password
}

Write-Debug "Username: '${Username}' Password: $('*' * $Password.Length)"
# Call the /oauth2/token endpoint, extract the access_token from the
# response and use it to create a Bearer token Authorization header
$headers = @{ 'Authorization' = 'Bearer ' + (
        Invoke-WebRequest -Body (@{
                'username'   = $Username
                'password'   = $Password | ConvertFrom-SecureString -AsPlainText
                'grant_type' = 'password'
            }
        ) -Method Post -Uri "${BaseUri}/oauth2/token" |
        ConvertFrom-Json).access_token
}
$discoveryUri = "${BaseUri}/api/v1/Discovery"

Write-Verbose "Attempting to get Discovery status"
$Status = Invoke-RestMethod -Headers $headers -Uri "${discoveryUri}/status"
Write-Debug "Status: ${Status}"

# Do nothing if Discovery is already running
if ($CommandType -eq "Discovery" -and $Status.isDiscoveryFetchRunning -or
    $CommandType -eq "ComputerScan" -and $Status.isDiscoveryComputerScanRunning) {
    Write-Information "${CommandType} is already running"
    return
}
Write-Verbose "Attempting to run ${CommandType}"
# /Discovery/run returns "True" or "False", so we can cast it as boolean
if (([boolean](
            Invoke-RestMethod -Headers $headers -ContentType "application/json" -Body (@{
                    "data" = @{
                        "commandType" = $CommandType
                    }
                } | ConvertTo-Json) -Method Post -Uri "${discoveryUri}/run"
        ))) {
    Write-Information "${CommandType} started"
}
