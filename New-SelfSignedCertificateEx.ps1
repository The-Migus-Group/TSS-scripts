<#
.SYNOPSIS

Create a self-signed RSA certificate

.DESCRIPTION

Generates a self-signed X.509 certificate then exports the Certificate to a CER
file and the Certificate Chain and Private Key to a PFX file.

.NOTES
The script must be run with Administrator privileges.

The certificate will only work with the Thycotic RabbitMQ Helper if the default
Cryptographic Provider (RSA) is used.

Copyright 2020, The Migus Group, LLC. All rights reserved
#>

Param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string[]] $SubjectAlternativeNames,
  [ValidateScript( { $_ -ge 1 })][int] $ExpirationInYears = 10,
  [ValidateScript( { $_ -ge 2048 })][int] $KeyLength = 4096,
  [ValidateScript( { $_ -in "SHA256", "SHA512" })][string] $HashAlgorithm = "SHA256",
  [securestring] $PfxPassword = (ConvertTo-SecureString $env:COMPUTERNAME -AsPlainText -Force),
  [string] $MyDnsName = ${env:COMPUTERNAME},
  [string] $CryptoProvider = "Microsoft Enhanced RSA and AES Cryptographic Provider",
  [string] $CertificateFileName = "${env:COMPUTERNAME}.cer",
  [string] $PfxFileName = "${env:COMPUTERNAME}.pfx"
)
# The each step requires the last so stop if we get an error
$ErrorActionPreference = "Stop"

# Create the self-signed certificate
$cert = New-SelfSignedCertificate -Subject $MyDnsName -DnsName $SubjectAlternativeNames -HashAlgorithm $HashAlgorithm -KeyLength $KeyLength -NotAfter (Get-Date).AddYears($ExpirationInYears) -Provider $CryptoProvider
# Export the certificate
Export-Certificate -Cert $cert -FilePath $CertificateFileName
# Export the PFX
Export-PfxCertificate -Cert $cert -FilePath $PfxFileName -Password $PfxPassword
