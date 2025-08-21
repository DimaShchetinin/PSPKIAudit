function Get-CertRequest {
    <#
    .SYNOPSIS

    Returns issued certificate requests with augmented security information.

    License: Ms-PL
    Required Dependencies: PSPKI

    .PARAMETER CAComputerName

    The name of the Certificate Authority computer to enumerate requests for.

    .PARAMETER CAName

    The name of the Certificate Authority to enumerate requests for.

    .PARAMETER HasSAN

    Switch. Only return issued certificates that has a Subject Alternative Name specified in the request.

    .PARAMETER Requester

    'DOMAIN\user' format. Only return issued certificate requests for the requester.

    .PARAMETER Template

    Only return return issued certificate requests for the specified template name.

    .PARAMETER Filter

    Custom filter to search for issued certificates.

    .EXAMPLE

    Get-CertRequest -CAName "theshire-DC-CA" -HasSAN

    Return requests with SANs for the "theshire-DC-CA".

    .EXAMPLE

    Get-CertRequest -CAComputerName dc.theshire.local -Requester THESHIRE\cody

    Return requests issue by THESHIRE\cody from the dc.theshire.local CA.

    .EXAMPLE

    Get-CertRequest -Template "VulnTemplate"

    Return requests for the "VulnTemplate" certificate template.
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $CAComputerName,

        [Parameter()]
        [String]
        $CAName,

        [Switch]
        $HasSAN,

        [String]
        $Requester,

        [String]
        [Alias('TemplateName', 'CertificateTemplate')]
        $Template,

        [String]
        $Filter
    )


    if($Requester -and (-not $Requester.Contains("\"))) {
        Write-Warning "-Requester must be of form 'DOMAIN\user'"
        return
    }


    if($Requester) {
        $Filter = "Request.RequesterName -eq $Requester"
    }


    $CAs = @()

    if($CAComputerName) {
        $CAs = Get-CertificationAuthority -ComputerName $CAComputerName
    }
    elseif($CAName) {
        $CAs = Get-CertificationAuthority -Name $CAName
    }
    else {
        $CAs = Get-CertificationAuthority
    }
    

    foreach($CA in $CAs) {
        if($Filter) {
            Write-Verbose "Filter: $Filter"
            $CA | Get-IssuedRequest -Filter "$Filter" -Property @('Request.RequesterName', 'Request.CommonName', 'Request.CallerName', 'Request.DistinguishedName', 'Subject', 'UPN', 'CommonName', 'DistinguishedName', 'Request.SubmittedWhen', 'CertificateTemplateOid', 'RequestID', 'ConfigString', 'Request.RawRequest', 'RawCertificate', 'EnrollmentFlags', 'CertificateTemplate') | ForEach-Object {
                    $IssuedRequest = $_ | Add-CertRequestInformation

                    $Base64Cert = $_.Properties["RawCertificate"]
                    # Write-Output $Base64Cert
                    $ExtensionList = Get-CertificateExtensions -Base64Cert $Base64Cert

                    if (-not [string]::IsNullOrWhiteSpace($ExtensionList.CertificateIssuancePolicies)) {
                        $IssuancePolicy = Get-OIDGroupInfo -PolicyString $ExtensionList.CertificateIssuancePolicies
                    }


                    $IssuedRequest | Select-Object -Property `
                    @{N='CA'; E={$_.ConfigString}}, `
                    @{N='Request.ID'; E={$_.RequestID}}, `
                    @{N='Request.RequesterName'; E={$_.'Request.RequesterName'}}, `                 
                    @{N='Request.CommonName'; E={$_.'Request.CommonName'}}, `
                    @{N='Request.CallerName'; E={$_.'Request.CallerName'}}, `
                    @{N='Request.DistinguishedName'; E={$_.'Request.DistinguishedName'}}, `
                    @{N='Request.ClientInformation.MachineName'; E={$_.MachineName}}, `
                    @{N='Request.ClientInformation.ProcessName'; E={$_.ProcessName}}, `
                    @{N='Request.ClientInformation.UserName'; E={$_.UserName}}, `
                    @{N='Request.SubjectAltNamesExtension'; E={$_.SubjectAltNamesExtension}}, `
                    @{N='Request.SubjectAltNamesAttrib'; E={$_.SubjectAltNamesAttrib}}, `
                    @{N='Request.ApplicationPolicies'; E={$_.ReqAppPolicies}}, `
                    @{N='UPN'; E={$_.UPN}}, `
                    @{N='Issued.DistinguishedName'; E={$_.'DistinguishedName'}}, `
                    @{N='Issued.CommonName'; E={$_.'CommonName'}}, `
                    @{N='CertificateTemplate'; E={$_.'CertificateTemplateOid'}}, `
                    @{N='EnrollmentFlags'; E={Decode-EnrollmentFlags -Mask $_.'EnrollmentFlags'}}, `
                    @{N='SerialNumber'; E={$_.SerialNumber}}, `
                    @{N='Certificate.SAN'; E={$ExtensionList.CertificateSAN}}, `
                    @{N='Certificate.ApplicationPolicies'; E={$ExtensionList.CertificateApplicationPolicies}}, `
                    @{N='Certificate.IssuancePolicies.PolicyName'; E={$IssuancePolicy.PolicyName}}, `
                    @{N='Certificate.IssuancePolicies.GroupCN'; E={$IssuancePolicy.GroupCN}}, `
                    @{N='Certificate.IssuancePolicies.GroupSID'; E={$IssuancePolicy.GroupSID}}, `
                    @{N='Certificate.EKU'; E={$ExtensionList.CertificateEKU}}, `
                    @{N='Certificate.SID_Extension.SID'; E={$ExtensionList.SidExtensionAccount.objectSid}}, `
                    @{N='Certificate.SID_Extension.DistinguishedName'; E={$ExtensionList.SidExtensionAccount.DistinguishedName}}, `
                    @{N='Certificate.SID_Extension.SamAccountName'; E={$ExtensionList.SidExtensionAccount.SamAccountName}}, `
                    @{N='Certificate.SID_Extension.UPN'; E={$ExtensionList.SidExtensionAccount.UserPrincipalName}}, `
                    @{N='Certificate.SID_Extension.CN'; E={$ExtensionList.SidExtensionAccount.CN}}, `
                    @{N='RequestDate'; E={$_.'Request.SubmittedWhen'}}, `
                    @{N='StartDate'; E={$_.NotBefore}}, `
                    @{N='EndDate'; E={$_.NotAfter}} | ForEach-Object {
                        if($HasSAN) {
                            if($_.SubjectAltNamesExtension -or $_.SubjectAltNamesAttrib) {
                                $_
                            }
                        }
                        else {
                            $_
                        }
                    } | ForEach-Object {
                        if($Template) {
                            if($_.CertificateTemplate -match $Template) {
                                $_
                            }
                        }
                        else {
                            $_
                        }
                    }
            }
        }
        else {
            # from https://github.com/PKISolutions/PSPKI/issues/144
            $PageSize = 50000
            $LastID = 0

            do {
                $ReadRows = 0
                $CA | Get-IssuedRequest -Filter "$($Filter)RequestID -gt $LastID" -Page 1 -PageSize $PageSize -Property @('Request.RequesterName', 'Request.CommonName', 'Request.CallerName', 'Request.DistinguishedName', 'Subject', 'UPN', 'CommonName', 'DistinguishedName', 'Request.SubmittedWhen', 'CertificateTemplateOid', 'RequestID', 'ConfigString', 'Request.RawRequest', 'RawCertificate', 'EnrollmentFlags', 'CertificateTemplate') | ForEach-Object {
                    $ReadRows++
                    $IssuedRequest = $_ | Add-CertRequestInformation

                    $Base64Cert = $_.Properties["RawCertificate"]
                    $ExtensionList = Get-CertificateExtensions -Base64Cert $Base64Cert

                    if (-not [string]::IsNullOrWhiteSpace($ExtensionList.CertificateIssuancePolicies)) {
                        $IssuancePolicy = Get-OIDGroupInfo -PolicyString $ExtensionList.CertificateIssuancePolicies
                    }

                    $IssuedRequest | Select-Object -Property `
                    @{N='CA'; E={$_.ConfigString}}, `
                    @{N='Request.ID'; E={$_.RequestID}}, `
                    @{N='Request.RequesterName'; E={$_.'Request.RequesterName'}}, `                 
                    @{N='Request.CommonName'; E={$_.'Request.CommonName'}}, `
                    @{N='Request.CallerName'; E={$_.'Request.CallerName'}}, `
                    @{N='Request.DistinguishedName'; E={$_.'Request.DistinguishedName'}}, `
                    @{N='Request.ClientInformation.MachineName'; E={$_.MachineName}}, `
                    @{N='Request.ClientInformation.ProcessName'; E={$_.ProcessName}}, `
                    @{N='Request.ClientInformation.UserName'; E={$_.UserName}}, `
                    @{N='Request.SubjectAltNamesExtension'; E={$_.SubjectAltNamesExtension}}, `
                    @{N='Request.SubjectAltNamesAttrib'; E={$_.SubjectAltNamesAttrib}}, `
                    @{N='Request.ApplicationPolicies'; E={$_.ReqAppPolicies}}, `
                    @{N='UPN'; E={$_.UPN}}, `
                    @{N='Issued.DistinguishedName'; E={$_.'DistinguishedName'}}, `
                    @{N='Issued.CommonName'; E={$_.'CommonName'}}, `
                    @{N='CertificateTemplate'; E={$_.'CertificateTemplateOid'}}, `
                    @{N='EnrollmentFlags'; E={Decode-EnrollmentFlags -Mask $_.'EnrollmentFlags'}}, `
                    @{N='SerialNumber'; E={$_.SerialNumber}}, `
                    @{N='Certificate.SAN'; E={$ExtensionList.CertificateSAN}}, `
                    @{N='Certificate.ApplicationPolicies'; E={$ExtensionList.CertificateApplicationPolicies}}, `
                    @{N='Certificate.IssuancePolicies.PolicyName'; E={$IssuancePolicy.PolicyName}}, `
                    @{N='Certificate.IssuancePolicies.GroupCN'; E={$IssuancePolicy.GroupCN}}, `
                    @{N='Certificate.IssuancePolicies.GroupSID'; E={$IssuancePolicy.GroupSID}}, `
                    @{N='Certificate.EKU'; E={$ExtensionList.CertificateEKU}}, `
                    @{N='Certificate.SID_Extension.SID'; E={$ExtensionList.SidExtensionAccount.objectSid}}, `
                    @{N='Certificate.SID_Extension.DistinguishedName'; E={$ExtensionList.SidExtensionAccount.DistinguishedName}}, `
                    @{N='Certificate.SID_Extension.SamAccountName'; E={$ExtensionList.SidExtensionAccount.SamAccountName}}, `
                    @{N='Certificate.SID_Extension.UPN'; E={$ExtensionList.SidExtensionAccount.UserPrincipalName}}, `
                    @{N='Certificate.SID_Extension.CN'; E={$ExtensionList.SidExtensionAccount.CN}}, `
                    @{N='RequestDate'; E={$_.'Request.SubmittedWhen'}}, `
                    @{N='StartDate'; E={$_.NotBefore}}, `
                    @{N='EndDate'; E={$_.NotAfter}} | ForEach-Object {
                        if($HasSAN) {
                            if($_.SubjectAltNamesExtension -or $_.SubjectAltNamesAttrib) {
                                $_
                            }
                        }
                        else {
                            $_
                        }
                    } | ForEach-Object {
                        if($Template) {
                            if($_.CertificateTemplate -match $Template) {
                                $_
                            }
                        }
                        else {
                            $_
                        }
                    }
                }
            } while ($ReadRows -eq $PageSize)
        }
    }
}



function Add-CertRequestInformation {
    <#
    .SYNOPSIS
    
    Adds SAN and REQUEST_CLIENT_INFO parsing to a raw AdcsDbRow.

    License: Ms-PL
    Required Dependencies: None
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbRow]
        $Request
    )

    $MachineName = ""
    $UserName = ""
    $ProcessName = ""
    $AltNameExtensions = @()
    $AltNameValuePairs = @()

    try {
        $RawRequestBytes = [Convert]::FromBase64String($Request.'Request.RawRequest')

        if($RawRequestBytes.Length -gt 0) {
            try {
                $CertRequest = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificateRequest (,$RawRequestBytes)
            }
            catch {
                Write-Verbose "Error parsing RequestID: $($Request.RequestID): $_"
                return
            }

            # scenario 1 for SAN specification -> using the explicit X509SubjectAlternativeNamesExtension
            #   this occurs with the EnrolleeSuppliesSubject scenario
            $Ext = $CertRequest.Extensions
            $Alt = $CertRequest.Extensions | Where-Object {$_.GetType().Name -eq "X509SubjectAlternativeNamesExtension"}
            $ReqAppPolicies = $Ext.ApplicationPolicies
            $AltNameExtensions += $Alt.AlternativeNames.Value

            $CertRequest.Attributes | ForEach-Object {
                if($_.Oid.Value -eq "1.3.6.1.4.1.311.21.20") {
                    # format - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/64e5ff6d-c6dd-4578-92f7-b3d895f9b9c7
                    $ASN = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,$_.RawData)
                    if(($ASN.Tag -eq 48) -and $ASN.MoveNext() -and ($ASN.Tag -eq 2) -and $ASN.MoveNext() -and ($ASN.Tag -eq 12)) {
                        $Bytes = $ASN.GetPayload()
                        $Encoding = [System.Text.UnicodeEncoding]::ASCII
                        if($Bytes -cmatch '[^\x20-\x7F]') {
                            $Encoding = [System.Text.UnicodeEncoding]::Unicode
                        }
                        $MachineName = $Encoding.GetString($asn.GetPayload())
                        $Null = $ASN.MoveNext()
                        $UserName = $Encoding.GetString($asn.GetPayload())
                        $Null = $ASN.MoveNext()
                        $ProcessName = $Encoding.GetString($asn.GetPayload())
                    }
                }
                if($_.Oid.Value -eq "1.3.6.1.4.1.311.13.2.1") {
                    # "Enrollment Name Value Pair"
                    $Index = 0
                    $Len = $_.RawData.Length
                    while($Index -lt $Len) {
                        $ASN = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,$_.RawData[$index..$Len])
                        $TagLen = $ASN.TagLength

                        if($ASN.Tag -eq 48) {
                            while($ASN.MoveNext()) {
                                $Name = [System.Text.UnicodeEncoding]::BigEndianUnicode.GetString($ASN.GetPayload())
                                $Null = $ASN.MoveNext()
                                if($Name -eq "SAN") {
                                    # scenario 2 for SAN specification -> attrib/name value pairs
                                    #   this occurs with the EDITF_ATTRIBUTESUBJECTALTNAME2 scenario
                                    $Value = [System.Text.UnicodeEncoding]::BigEndianUnicode.GetString($ASN.GetPayload())
                                    $AltNameValuePairs += $Value.Split("=")[-1]
                                }
                            }
                        }
                        $Index += $TagLen
                    }
                }
                if($_.Oid.Value -eq "1.3.6.1.4.1.311.21.20") {
                    # format - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/64e5ff6d-c6dd-4578-92f7-b3d895f9b9c7
                    $ASN = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,$_.RawData)
                    if(($ASN.Tag -eq 48) -and $ASN.MoveNext() -and ($ASN.Tag -eq 2) -and $ASN.MoveNext() -and ($ASN.Tag -eq 12)) {
                        $Bytes = $ASN.GetPayload()
                        $Encoding = [System.Text.UnicodeEncoding]::ASCII
                        if($Bytes -cmatch '[^\x20-\x7F]') {
                            $Encoding = [System.Text.UnicodeEncoding]::Unicode
                        }
                        $MachineName = $Encoding.GetString($asn.GetPayload())
                        $Null = $ASN.MoveNext()
                        $UserName = $Encoding.GetString($asn.GetPayload())
                        $Null = $ASN.MoveNext()
                        $ProcessName = $Encoding.GetString($asn.GetPayload())
                    }
                }
            }
        }
    }
    catch {
        Write-Error $_
    }

    $SubjectAltNamesExtension = $($AltNameExtensions | Sort-Object -Unique) -join "|"
    $SubjectAltNamesAttrib = $($AltNameValuePairs | Sort-Object -Unique) -join "|"
    $Request | Add-Member NoteProperty 'MachineName' $MachineName
    $Request | Add-Member NoteProperty 'UserName' $UserName
    $Request | Add-Member NoteProperty 'ProcessName' $ProcessName
    $Request | Add-Member NoteProperty 'SubjectAltNamesExtension' $SubjectAltNamesExtension
    $Request | Add-Member NoteProperty 'SubjectAltNamesAttrib' $SubjectAltNamesAttrib
    $Request | Add-Member NoteProperty 'ReqAppPolicies' $ReqAppPolicies
    $Request
}


function Get-SIDFromBytes {
    param(
        [byte[]]$Bytes
    )
    $pattern = [System.Text.Encoding]::ASCII.GetBytes("S-1-5-21")

    $foundIndex = -1
    for ($i = 0; $i -le $Bytes.Length - $pattern.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $pattern.Length; $j++) {
            if ($Bytes[$i + $j] -ne $pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $foundIndex = $i
            break
        }
    }

    if ($foundIndex -eq -1) {
        throw "SID wasn't found"
    }

    $sidBytes = $Bytes[$foundIndex..($Bytes.Length - 1)]
    return [System.Text.Encoding]::ASCII.GetString($sidBytes)
}

function Get-CertificateExtensions {
    <#
    .SYNOPSIS
        Parses extension list Information from a Base64 encoded X509 certificate.

    .DESCRIPTION
        Accepts a Base64-encoded certificate (PEM or raw base64) and returns full extension list

    .PARAMETER Base64Cert
        Base64 encoded X509 certificate string.

    .EXAMPLE
        $certInfo = Get-CertificateExtensions -Base64Cert $certBase64
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$Base64Cert
    )

        $Base64Cert = $Base64Cert -replace '\s',''

        $certBytes = [Convert]::FromBase64String($Base64Cert)

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

        foreach ($ext in $cert.Extensions) {
          if ($ext.Oid.Value -eq "2.5.29.17") {
               $san = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
               $san.Format($true)
          }

          # Application Policies  -  OID: 1.3.6.1.4.1.311.21.10
          if ($ext.Oid.Value -eq "1.3.6.1.4.1.311.21.10") {
               $app_policies = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
                if ($null -ne $app_policies) {
                    $formatted_app_policies = $app_policies.Format($false)
                } else {
                    $formatted_app_policies = ""
                }
          }
          # Certificate Policies  -  OID: 2.5.29.32 (IssuancePolicy)
          if ($ext.Oid.Value -eq "2.5.29.32") {
               $issuance_policies = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
                if ($null -ne $issuance_policies) {
                    $formatted_issuance_policies = $issuance_policies.Format($false)
                } else {
                    $formatted_issuance_policies = ""
                }
          }
          # Enhanced Key Usage  -  OID: 2.5.29.37
          if ($ext.Oid.Value -eq "2.5.29.37") {
               $ekus = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
                if ($null -ne $ekus) {
                    $formatted_ekus = $ekus.Format($false)
                } else {
                    $formatted_ekus = ""
                }
          }

          if ($ext.Oid.Value -eq "1.3.6.1.4.1.311.25.2") {
              $sidString = Get-SIDFromBytes -Bytes  $ext.RawData
              $account = Get-ADObject -Filter { objectSid -eq $sidString } -Properties DistinguishedName, SamAccountName, UserPrincipalName, CN, objectSid

          }
        }  
        [PSCustomObject]@{
            CertificateSAN                   = $san.Format($false)
            CertificateApplicationPolicies   = $formatted_app_policies
            CertificateIssuancePolicies      = $formatted_issuance_policies
            CertificateEKU                   = $formatted_ekus
            SidExtensionAccount              = $account
        }
    

}

function Decode-EnrollmentFlags {
    param (
        [Parameter(Mandatory = $true)]
        [int]$Mask
    )

    # Define the flags as a hashtable
    $flags = @{
        'CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS'                                  = 0x00000001
        'CT_FLAG_PEND_ALL_REQUESTS'                                             = 0x00000002
        'CT_FLAG_PUBLISH_TO_KRA_CONTAINER'                                      = 0x00000004
        'CT_FLAG_PUBLISH_TO_DS'                                                 = 0x00000008
        'CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE'                     = 0x00000010
        'CT_FLAG_AUTO_ENROLLMENT'                                               = 0x00000020
        'CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT'                       = 0x00000040
        'CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED'                            = 0x00000080
        'CT_FLAG_USER_INTERACTION_REQUIRED'                                     = 0x00000100
        'CT_FLAG_ADD_TEMPLATE_NAME'                                             = 0x00000200
        'CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE'                = 0x00000400
        'CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF'                                     = 0x00000800
        'CT_FLAG_ADD_OCSP_NOCHECK'                                              = 0x00001000
        'CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL'              = 0x00002000
        'CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS'                                 = 0x00004000
        'CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS'                        = 0x00008000
        'CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT' = 0x00010000
        'CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST'                                = 0x00020000
        'CT_FLAG_SKIP_AUTO_RENEWAL'                                             = 0x00040000
        'CT_FLAG_NO_SECURITY_EXTENSION'                                         = 0x00080000
    }

    $setFlags = @()

    foreach ($flag in $flags.GetEnumerator()) {
        if ($Mask -band $flag.Value) {
            $setFlags += $flag.Key
        }
    }
    return $setFlags   
}


function Get-OIDGroupInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PolicyString
    )

    if ($PolicyString -match 'Policy Identifier=([\w-]+)') {
        $policyName = $matches[1]
    } else {
        Write-Error "Policy Identifier wasn't found in provided string"
        return
    }

    $rootDse = Get-ADRootDSE
    $configNC = $rootDse.configurationNamingContext

    $oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

    $oidObject = Get-ADObject -Filter "displayName -eq '$policyName'" -SearchBase $oidContainer -Properties msDS-OIDToGroupLink

    if (-not $oidObject) {
        Write-Error "Object with CN=$policyName wasn't found in $oidContainer."
        return
    }

    if ($oidObject.'msDS-OIDToGroupLink') {
        $groupDN = $oidObject.'msDS-OIDToGroupLink'
        $group = Get-ADGroup -Identity $groupDN -Properties SID, CN

        [PSCustomObject]@{
            PolicyName = $policyName
            GroupCN    = $group.CN
            GroupSID   = $group.SID.Value
        }
    }
    else {
        Write-Output ""
    }
}