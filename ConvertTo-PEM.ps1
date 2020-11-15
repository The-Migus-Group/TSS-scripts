<#
.SYNOPSIS

Convert an X.509 certeificate from CER (DER) format to PEM format.

.DESCRIPTION

Converts the specified X.509 certificate from CER (DER) format to
PEM (base 64) format.

Copyright 2020, The Migus Group, LLC. All rights reserved
#>

[CmdletBinding(DefaultParameterSetName = 'Input')]
Param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Input', Position = 0)]
  [Parameter(Mandatory = $true, ParameterSetName = 'Pipeline', ValueFromPipeline = $true)]
  [System.Security.Cryptography.X509Certificates.X509Certificate2]
  $Certificate,
  [Parameter(ParameterSetName = "Input", Position = 1)]
  [Parameter(ParameterSetName = "Pipeline", Position = 0)]
  $OutFilePath
)

$output = New-Object System.Text.StringBuilder
[void]$output.AppendLine("-----BEGIN CERTIFICATE-----")
[void]$output.AppendLine([System.Convert]::ToBase64String($Certificate.RawData, 1))
[void]$output.AppendLine("-----END CERTIFICATE-----")

if ($null -ne $OutFilePath) {
    $output.ToString()
    | Out-File -Encoding UTF8 -FilePath $OutFilePath -NoClobber -NoNewline
} else {
    $output.ToString()
    | Out-String -NoNewline
}
