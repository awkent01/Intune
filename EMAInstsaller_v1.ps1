# Intel(R) EMA AMT detection and agent install utility
# Author: Grant Kelly, grant.l.kelly@intel.com
#
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see https://protect-us.mimecast.com/s/RtMMC73JV3TmWvBqVfq_eqy?domain=gnu.org
#
#
#Requires -Version 5
param (
    [Parameter(Mandatory = $false, Position=0)]
    [string]$action, 
    [Parameter(Mandatory = $false, Position=1)]
    [string]$helpparam, 
    [Parameter(Mandatory = $false, Position=2)]
    [string]$server, 
    [Parameter(Mandatory = $false, Position=3)]
    [string]$user, 
    [Parameter(Mandatory = $false, Position=4)]
    [string]$password,
    [Parameter(Mandatory = $false, Position=5)]
    [string]$vproepg,
    [Parameter(Mandatory = $false, Position=6)]
    [string]$novproepg,
    [Parameter(Mandatory = $false, Position=7)]
    [switch]$ad,
    [Parameter(Mandatory = $false, Position=8)]
    [switch]$na,
    [Parameter(Mandatory = $false, Position=9)]
    [switch]$noverify,
    [Parameter(Mandatory = $false, Position=10)]
    [switch]$dryrun
)
# Function definition section
#
# Sequential or designated token creation for Active Directory or normal accounts

#Script filepath
$ScriptLocation = "C:\temp\INTEL EMA"

function Get-AuthToken {
    $global:authenticated = $false
    $global:emasrv = $server
    Write-Host -Foreground Cyan "Server: $emasrv User: $user Password: ***********"
    $body = @{
        "Password" = $password
        "Upn" = $user
    }
    $json = $body | ConvertTo-Json
    If ($ad) {
        try {
            $token = (Invoke-RestMethod -Uri https://$emasrv/api/latest/accessTokens/getUsingWindowsCredentials -ContentType 'application/json' -Method POST -Body $json) | Select-Object -Expand access_token
            $global:headers = @{'Authorization' = 'Bearer ' + $token}
            Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
            $global:authenticated = $true
        } catch {Write-Host -Foreground Yellow "Unable to authenticate using Active Directory credentials."}
    } ElseIf ($na) {
        try {
            $token = (Invoke-RestMethod -Uri https://$emasrv/api/token -Method POST -Body "grant_type=password&username=$user&password=$password") | Select-Object -Expand access_token
            $global:headers = @{'Authorization' = 'Bearer ' + $token}
            Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
            $global:authenticated = $true
        } catch {Write-Host -Foreground Yellow "Unable to authenticate using normal account credentials."}
    } Else {
        try {
            $token = (Invoke-RestMethod -Uri https://$emasrv/api/latest/accessTokens/getUsingWindowsCredentials -ContentType 'application/json' -Method POST -Body $json) | Select-Object -Expand access_token
            $global:headers = @{'Authorization' = 'Bearer ' + $token}
            Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
            $global:authenticated = $true
        } catch {Write-Host -Foreground Yellow "Unable to authenticate using Active Directory credentials.`nAttempting to use normal account credentials...`n"}
    If ($authenticated -eq $true) {Return}
        try {
            $token = (Invoke-RestMethod -Uri https://$emasrv/api/token -Method POST -Body "grant_type=password&username=$user&password=$password") | Select-Object -Expand access_token
            $global:headers = @{'Authorization' = 'Bearer ' + $token}
            Write-Host -Foreground Green "Authentication token for server $emasrv using account $user created successfully."
            $global:authenticated = $true
        } catch {Write-Host -Foreground Yellow "Unable to authenticate using normal account credentials."}
        If ($authenticated -eq $true) {
            Return
        }
        If ($authenticated -eq $false) {
            Write-Host -Foreground Yellow "`nUnable to authenticate using either type of credential.  Is the server, username and password correct?"
        }
    }
}

# Get agent and policy file a specific endpoint group
function Get-AgentFiles {
    $services = (sc.exe query)
    $t = 0
    #Filepath for emaconfig zip
    $EMAZip = "\\server\folder\emaconfigtool_1.0.2.80.zip"
    foreach ($_ in $services) {
        If ($services[$t] -like "SERVICE_NAME: EmaAgent") {
            $emainstalled = $true
            Write-Host -ForegroundColor Green "Intel(R) EMA Agent installed!"
        }
    $t++
    }
    If ($emainstalled -And !($dryrun)) {
        Return
    }
    If (!(Test-Path "$PSScriptRoot\EMAConfigTool.exe")) {
        $guid = (New-Guid).Guid
        (New-Item -Path "$env:temp" -Name "$guid" -ItemType "directory") | Out-Null
        $workingdir = $env:temp+"\"+$guid
        [int]$dc = 0
        do {
            $hash = $null
            $dc = $dc+1
            (Copy-Item $EMAZip -Destination $workingdir -Force -Recurse ) | Out-Null
            $hash = ((Get-FileHash -Path "$workingdir\EMAConfigTool.zip" -Algorithm SHA1) | Select-Object -Expand Hash)
            If ($dc -ge 3) {
                (Invoke-WebRequest -Uri https://emacloudstart.z13.web.core.windows.net/packages/EMAConfigTool.zip -OutFile "$workingdir\EMAConfigTool.zip") | Out-Null
                Break
            }
        } until ($hash -eq "9269FA4B748F92DC9A1B22FCBA8DB2F2B0A349F2")
        (Expand-Archive "$workingdir\EMAConfigTool.zip" -DestinationPath "$workingdir") | Out-Null
        (New-Item -Path "$workingdir" -Name "extracted" -ItemType "directory") | Out-Null
        (msiexec /a "$workingdir\EMAConfigTool.msi" /qn TARGETDIR="$workingdir\extracted") | Out-Null
        $workingdir = "$workingdir\extracted\PFiles\Intel\EMAConfigTool"
        $removedir = $true
        Start-Sleep 2
    } ElseIf (Test-Path "$PSScriptRoot\EMAConfigTool.exe") {
        $workingdir = "$PSScriptRoot"
    }
    (& "$workingdir\EMAConfigTool.exe" --writejson --noregistry --noconsole --filepath $workingdir --filename amtinfo) | Out-Null
    $amtinfo = (Get-Content $workingdir\amtinfo.json)
    $global:version = ($amtinfo | ConvertFrom-JSON).System.MEFirmwareInfo.MEVersion
    $global:state = ($amtinfo | ConvertFrom-JSON).System.MEFirmwareInfo.MEProvisioningState
    If (!($version -match "^\d.+$")) {
        $global:amt_enable = $false
    } ElseIf ($version -match "^\d.+$") {
        $global:amtver = $version.Split(".")
        [int]$global:major = $amtver[0]
        [int]$global:minor = $amtver[1]
        If (($major -ge $vermajor -And $minor -ge $verminor) -Or ($major -ge ($vermajor+1))) {
            $global:amt_enable = $true
        } Else {
            $global:amt_enable = $false
        }
    }
    If ($state -eq "Provisioned") {
        $global:amt_state = $true
    } Else {
        $global:amt_state = $false
    }
    Remove-Item $workingdir\amtinfo.json
    If ($removedir) {
        Remove-Item "$env:temp\$guid" -Force -Recurse
    }
    Write-Host -ForegroundColor Cyan "AMT version: $version`nAMT status: $state"
    If ($amt_enable -eq $true -And $amt_state -eq $true) {
        # Write-Host -Foreground Green "Endpoint appears to be provisioned already..."
        If (!($dryrun)) {
            Write-Host -Foreground Green "Endpoint appears to be provisioned already...exiting."
            Exit
        } Else {
            Write-Host -Foreground Green "Endpoint appears to be provisioned already..."
        }
    }
    $reauth = $null
    If ([string]::IsNullOrEmpty($user)) {
        $reauth = $false
    } Else {
        $reauth = $true
    }
    If ($reauth -eq $true) {
        Get-AuthToken
    }
    $global:emasrv = $server
    try {
        If ($amt_enable -eq $false -And $amt_state -eq $false) {
            $endpointgroupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $novproepg | Select-Object -Expand EndpointGroupId)
            Write-Host -ForegroundColor Green "non-vPro or firmware older than v$vermajor.$verminor endpoint detected!"
        } ElseIf ($amt_enable -eq $true -And $amt_state -eq $false) {
            $endpointgroupid = ((Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups -ContentType 'application/json' -Method GET -Headers $headers) | Where-Object -Property Name -eq $vproepg | Select-Object -Expand EndpointGroupId)
            Write-Host -ForegroundColor Green "vPro endpoint detected!"
        } ElseIf ($amt_enable -eq $true -And $amt_state -eq $true) {
            If (!($dryrun)) {
                Write-Host -Foreground Green "Endpoint appears to be provisioned already...exiting."
                Exit
            } Else {
                Write-Host -Foreground Green "Endpoint appears to be provisioned already..."
            }
        }
        If (!($dryrun)) {
            Invoke-RestMethod -Uri https://$emasrv/api/latest/agents/getWin64Service -Method GET -Headers $headers -OutFile "$env:temp\EMAAgent.exe"
            Invoke-RestMethod -Uri https://$emasrv/api/latest/endpointGroups/$endpointgroupid/getMshFile -Method GET -Headers $headers -OutFile "$env:temp\EMAAgent.msh"
            Write-Host -Foreground Green "Successfully downloaded agent installation and policy files to $env:temp."
            cd "$env:temp"
            & ".\EMAAgent.exe" -fullinstall
            cd "$PSScriptRoot"
        } ElseIf ($dryrun) {
            Write-Host -ForegroundColor Green "Test run only...if we reached this point, agent would have been installed for the appropriate platform mentioned above"
        }
    } catch {Write-Host -Foreground Yellow "Unable to get agent and policy files from $emasrv.  Did you authenticate with tenant admin credentials?"}
}

# Set certificate handling for < Windows 11 first if -noverify option set to true
$psver = ($PSVersionTable.PSVersion).ToString()
If ($noverify -And $psver -lt 6) {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
} ElseIf ($noverify -And $psver -ge 6) {
    $PSDefaultParameterValues["Invoke-RestMethod:SkipCertificateCheck"]=$true
}

# Main execution
# Set min firmware version for install.  As of Intel EMA 1.6.1, v11.8 and greater is supported
[int]$global:vermajor = 11
[int]$global:verminor = 8

# Call functions based on first argument
If ($action -eq "Get-AuthToken") {
 Get-AuthToken
} ElseIf ($action -eq "Get-AgentFiles") {
 Get-AgentFiles
}  Else {
 Write-Host " Must specify one action.  Available actions:

 Get-AuthToken			Get an authentication token by attempting AD auth and then normal account auth
 Get-AgentFiles			Downloads the agent installation and policy file for x64"
}


Set-Location $ScriptLocation
.\EMAInstsaller.ps1 Get-AgentFiles -server "SERVERNAME" -user "USER" -password "PASSWORD" -vproepg "Default Admin Control" -novproepg "Non Vpro Default" -noverify -na