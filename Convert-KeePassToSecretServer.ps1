<#
.SYNOPSIS
Converts a KeePass XML (2.x) file to a Thycotic Secret Server Import XML file.

.DESCRIPTION
Converts Groups and Entries in a KeepPass 2.x XML Export file to Folders and Secrets in a Thycotic Secret Server
Import XML file.

.NOTES
If the RootFolderPath is not a leaf then the parent folders of the leaf folder must already exist.


Copyright 2021, The Migus Group, LLC. All rights reserved
#>


#region Parameters
[CmdletBinding()]
Param(
    # The KeyPass XML (2.x) file
    [Parameter(Mandatory)][System.IO.FileInfo] $KeePassXmlPath,

    # The Path of the root folder in Secret Server
    [Parameter(Mandatory)][string] $RootFolderPath,

    # The Owner of any created Folders (default 'admin')
    [Parameter()][string] $FolderOwner = 'admin',

    # The Site ID of any created Secrets (default 1)
    [Parameter()][int] $SiteId = 1,

    # The System Site ID (default -1)
    [int] $SystemSiteId = -1,

    # The Template XML for a Folder in Secret Server Import XML
    [String] $FolderXml = @'
<Folder>
    <FolderName>{0}</FolderName>
    <FolderPath>{1}</FolderPath>
    <Permissions>
        <Permission>
        <SecretAccessRoleName>{2}</SecretAccessRoleName>
        <FolderAccessRoleName>{3}</FolderAccessRoleName>
        <UserName>{4}</UserName>
        </Permission>
    </Permissions>
    <MappedSecretTypes />
</Folder>
'@,

    # A table of Secret Server Template to Import XML Template mappings
    $SecretsXml = @{
        'Active Directory' = @'
<Secret>
    <SecretName>{0}</SecretName>
    <SecretTemplateName>Active Directory Account</SecretTemplateName>
    <FolderPath>{1}</FolderPath>
    <SiteId>-1</SiteId>
    <SecretItems>
        <SecretItem>
            <FieldName>Domain</FieldName>
            <Value>{2}</Value>
        </SecretItem>
        <SecretItem>
            <FieldName>Username</FieldName>
            <Value>{3}</Value>
        </SecretItem>
        <SecretItem>
            <FieldName>Password</FieldName>
            <Value><![CDATA[{4}]]></Value>
            </SecretItem>
        <SecretItem>
            <FieldName>Notes</FieldName>
            <Value><![CDATA[{5}]]></Value>
            </SecretItem>
    </SecretItems>
    <SecretDependencies />
    <SecretDependencyGroups />
    <Permissions />
</Secret>
'@
        'Web Password'     = @'
<Secret>
<SecretName>{0}</SecretName>
<SecretTemplateName>Web Password</SecretTemplateName>
<FolderPath>{1}</FolderPath>
<SiteId>-1</SiteId>
<SecretItems>
    <SecretItem>
    <FieldName>URL</FieldName>
    <Value>{2}</Value>
    </SecretItem>
    <SecretItem>
    <FieldName>UserName</FieldName>
    <Value>{3}</Value>
    </SecretItem>
    <SecretItem>
    <FieldName>Password</FieldName>
    <Value><![CDATA[{4}]]></Value>
    </SecretItem>
    <SecretItem>
    <FieldName>Notes</FieldName>
    <Value><![CDATA[{5}]]></Value>
    </SecretItem>
</SecretItems>
<SecretDependencies />
<SecretDependencyGroups />
<Permissions />
</Secret>
'@
        'Password'         = @'
<Secret>
<SecretName>{0}</SecretName>
<SecretTemplateName>Password</SecretTemplateName>
<FolderPath>{1}</FolderPath>
<SiteId>-1</SiteId>
<SecretItems>
    <SecretItem>
    <FieldName>Resource</FieldName>
    <Value>{2}</Value>
    </SecretItem>
    <SecretItem>
    <FieldName>Username</FieldName>
    <Value>{3}</Value>
    </SecretItem>
    <SecretItem>
    <FieldName>Password</FieldName>
    <Value><![CDATA[{4}]]></Value>
    </SecretItem>
    <SecretItem>
    <FieldName>Notes</FieldName>
    <Value><![CDATA[{5}]]></Value>
    </SecretItem>
</SecretItems>
<SecretDependencies />
<SecretDependencyGroups />
<Permissions />
</Secret>
'@
    }
)
#endregion
#region Functions
<#
.SYNOPSIS
Gets Secret Server Folder XML for every KeePass Group in the KeePass XML

.DESCRIPTION
Iterates KeePass Groups depth-first, emitting a Secret Server Folder for each one.

.NOTES
The function is recursive.
#>
function Get-FoldersFromKeePassGroups {
    Param(
        # The current Group
        [System.Xml.XmlElement]$Element,

        # The Path in which to root this Group in when creating Secret Server Folders
        [String[]]$Path
    )

    $FolderXml -f (
        $Path[-1] -replace '.*?([^/\\]+)$', '$1' # The name is the Basename of the Folder
    ), (
        '\' + ($Path.Trim('/', '\') -join '\') # Canonicalized Folder path
    ),
    'Owner', # Folder Permission
    'Owner', # Secret Permission
    $FolderOwner

    if ($Element.Group) {
        ForEach ($Group in $Element.Group) {
            if ($Group.Name -and 'Entry' -ne $Group.Name) {
                Get-FoldersFromKeePassGroups -Element $Group -Path ($Path + $Group.Name)
            }
        }
    }
}

<#
.SYNOPSIS
Gets Secret Server Secret XML for every KeePass Entry

.DESCRIPTION
Iterates KeePass Entries depth-first, emitting a Secret for each one.
It conditionally selects the Secret Template from the XML templates as follows:
- If the Entry has a "DOMAIN" then create an Active Directory Secret
- Else If the Entry contains a URL then create a Web Password Secret
- Otherwise create a Password Secret
  - Use "Machine," "Server," or "Host," in that order, as the "Resource," if the Entry contains it

.NOTES
The function is recursive.
#>
function Get-SecretsFromKeePassEntries {
    Param(
        # The current Entry
        [System.Xml.XmlElement]$Element,

        # The Path in which to root this Entry in when creating Secret Server Folders
        [String[]]$Path
    )

    if ($Element.Group) {
        ForEach ($Group in $Element.Group) {
            if ('Entry' -ne $Group.Name) {
                Get-SecretsFromKeePassEntries -Element $Group -Path ($Path + $Group.Name)
            }
        }
    }

    if ($Element.Entry) {
        ForEach ($entry in $Element.Entry) {
            $CanonicalPath = '\' + ($Path.Trim('/', '\') -join '\')
            $Fields = @{}

            ForEach ($field in 'Title', 'UserName', 'Password', 'DOMAIN', 'URL', 'Notes') {
                $Fields[$field] = $entry.SelectSingleNode('String[Key="' + $field + '"]/Value').'#text'
            }

            if ($Fields.DOMAIN) {
                $SecretsXml['Active Directory'] -f $Fields.Title, $CanonicalPath, $Fields.DOMAIN, $Fields.UserName,
                $Fields.Password, $Fields.Notes
            } elseif ($Fields.URL) {
                $SecretsXml['Web Password'] -f $Fields.Title, $CanonicalPath, $Fields.URL, $Fields.UserName,
                $Fields.Password, $Fields.Notes
            } else {
                :out ForEach ($field in 'Machine', 'Server', 'Host' ) {
                    $Fields.Resource = $entry.SelectSingleNode('String[Key="' + $field + '"]/Value').'#text'
                    if ($Fields.Resource) { break :out }
                }
                $SecretsXml['Password'] -f $Fields.Title, $CanonicalPath, $Fields.Resource, $Fields.UserName,
                $Fields.Password, $Fields.Notes
            }
        }
    }
}
#endregion

$Parameters = @{
    Element = ([XML](Get-Content $KeePassXmlPath)).KeePassFile.Root # Start from the Root node
    Path    = $RootFolderPath
}

# This is the minimum structure that Secret Server expects in an XML Import
@"
<?xml version='1.0' encoding='utf-8'?>
<ImportFile>
  <Folders>
    $(Get-FoldersFromKeePassGroups @Parameters)
  </Folders>
  <SecretTemplates />
  <Secrets>
    $(Get-SecretsFromKeePassEntries @Parameters)
  </Secrets>
  <Groups />
  <Sites>
    <SystemSiteId>$($SystemSiteId)</SystemSiteId>
  </Sites>
  <SiteConnectors />
</ImportFile>
"@
