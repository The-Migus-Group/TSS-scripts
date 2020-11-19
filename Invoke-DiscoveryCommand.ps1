<#
.SYNOPSIS
    Run a Thycotic Secret Server Discovery or ComputerScan

.DESCRIPTION
    Call the Thycotic Secret Server REST API /Discovery/run endpoint to
    run a Discovery or ComputerScan and, if successful, call the /status
    endpoint to confirm that it is running.


Copyright 2020, The Migus Group, LLC. All rights reserved
#>

[CmdletBinding(DefaultParameterSetName = 'UserPass')]
Param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript( { $_ -in @("ComputerScan", "Discovery")} )]
    [string]$CommandType = "Discovery",
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$BaseUrl = ${env:TSS_SERVER_URL},
    [Parameter(Mandatory = $true, ParameterSetName = "UserPass", Position = 2)]
    [string]$Username = ${env:TSS_USERNAME},
    [Parameter(Mandatory = $true, ParameterSetName = "UserPass", Position = 3)]
    [SecureString]$Password = (ConvertTo-SecureString -AsPlainText ${env:TSS_PASSWORD} -Force),
    [Parameter(Mandatory = $true, ParameterSetName = "Credential", Position = 2)]
    [ValidateScript( { $null -ne $_.Username } )]
    [PSCredential]$Credential
)
$ErrorActionPreference = 'Stop'

if ($null -ne $Credential) {
    $Username = $Credential.Username
    $Password = $Credential.Password
}
# Call the /oauth2/token endpoint, extract the access_token from the
# response and use it to create a Bearer token Authorization header
$headers = @{ 'Authorization' = 'Bearer ' + (
        Invoke-WebRequest -Body (@{
                'username' = $Username;
                'password' = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                )
                'grant_type' = 'password';
            }) -Method Post -Uri "${BaseUrl}/oauth2/token"
        | ConvertFrom-Json).access_token
}

# Call /Discovery/run and if it succeeds then call /Discovery/status
$discoveryApiUrl = "${BaseUrl}/api/v1/Discovery"
# /Discovery/run returns "True" or "False", so we can cast it as boolean
if (([boolean](
    Invoke-RestMethod -Headers $headers -Body (@{
        "data" = @{
            "commandType" = $CommandType
        }
    } | ConvertTo-Json) -Method Post -Uri "${discoveryApiUrl}/run"
))) {
    Invoke-RestMethod -Headers $headers -Uri "${discoveryApiUrl}/status"
}
