<#
.SYNOPSIS

Installs RabbitMQ with TLS using the Thycotic RabbitMQ Helper

.DESCRIPTION

Generates a self-signed X.509 certificate and uses the Thycotic RabbitMQ Helper
to install RabbitMQ with TLS using that certificate.

.NOTES

The script must be run with Administrator privileges.

Copyright 2020, The Migus Group, LLC. All rights reserved
#>

Param(
  [Parameter(Mandatory = $true, Position = 0)][string] $LoadBalancerDnsName,
  [ValidateScript( { $_ -ge 1 })][int] $Years = 10,
  [ValidateScript( { $_ -ge 2048 })][int] $KeyLength = 4096,
  [ValidateScript( { $_ -in "SHA256" })][string] $HashAlgorithm = "SHA256",
  [pscredential] $SiteConnectorCredentials = (Get-Credential -Message "Site Connector Credentials"),
  [string] $CryptographicProvider = "Microsoft Enhanced RSA and AES Cryptographic Provider",
  [securestring] $PfxPassword = (ConvertTo-SecureString $env:COMPUTERNAME -AsPlainText -Force),
  [string] $MyDnsName = ${env:COMPUTERNAME},
  [string] $CertificateFileName = "${env:COMPUTERNAME}.cer",
  [string] $PfxFileName = "${env:COMPUTERNAME}.pfx",
  [ValidateScript( { Test-Path -Path $_ -PathType 'Leaf' } )]
  [string] $RMQHelperPSModulePath = "${env:ProgramFiles}\Thycotic Software Ltd\RabbitMq Helper\Thycotic.RabbitMq.Helper.PSCommands.dll"
)

# The each step requires the last so stop if we get an error
$ErrorActionPreference = "Stop"

Import-Module $RMQHelperPSModulePath

# Create the self-signed certificate
$cert = New-SelfSignedCertificate -Subject $MyDnsName -DnsName $MyDnsName, $LoadBalancerDnsName -NotAfter (Get-Date).AddYears($Years) -HashAlgorithm $HashAlgorithm -KeyLength $KeyLength -Provider $CryptographicProvider

# Export the certificate
Export-Certificate -Cert $cert -FilePath $CertificateFileName

# Export the PFX
Export-PfxCertificate -Cert $cert -FilePath $PfxFileName -Password $PfxPassword

# Move the certificate to the Trusted Root Certificate Store
Move-Item ("Cert:\LocalMachine\My\" + $cert.GetCertHashString()) Cert:\LocalMachine\Root

# Call the Thycotic RabbitMQ Helper
Install-Connector -AgreeErlangLicense -AgreeRabbitMqLicense -Credential $SiteConnectorCredentials -CaCertPath "${PWD}\\$CertificateFileName" -Hostname $MyDnsName -PfxPath "${PWD}\\$PfxFileName" -PfxCredential (New-Object System.Management.Automation.PSCredential -ArgumentList ("ignored", $PfxPassword)) -UseTls -Verbose
