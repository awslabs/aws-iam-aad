<#Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  or in the "license" file accompanying this file. This file is distributed 
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
  express or implied. See the License for the specific language governing 
  permissions and limitations under the License.#>

param (
    [Parameter(Mandatory=$true)]
    [string] $azureADTenantName,
    [string] $azureUserName, 
    [string] $azurePassword,
    [parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string] $manifestJson
)

if ([String]::IsNullOrWhiteSpace($manifestJson))
{
	foreach ($i in $input)
	{
		if ($i.ToString().StartsWith("{"))
		{
			$manifestJson = $i;
			break;
		}
	}
}
elseif ([System.IO.File]::Exists($manifestJson))
{
	$manifestJson = [System.IO.File]::ReadAllText($manifestJson);
}

#region defining directory separator character based on environment OS
$dirChar = "\"
if ([Environment]::OSVersion.Platform -eq "Unix")
{
	$dirChar = "/"
}
#endregion

#Imported from ExtractIAMRoles
#############################
function ReadManifestJson()
{
    $manifestObj = ConvertFrom-Json -InputObject $manifestJson;
    return $manifestObj;
}
#############################

function Get-MSGraphToken($azureADTenantName, $azureUserName, $azurePassword)
{
    #region Validating parameters
    if ([System.String]::IsNullOrWhiteSpace($azureUserName) -or [System.String]::IsNullOrWhiteSpace($azurePassword))
    {
	    $message = "Please enter your Azure credentials. Your Azure user must be on Azure tenant {0}, and be assigned with Global Admin role on this tenant." -f $azureADTenantName
	    if ([System.String]::IsNullOrWhiteSpace($azureUserName))
        {
            $credential = Get-Credential -Message $message
        }
        else
        {
            $credential = Get-Credential -UserName $azureUserName -Message $message
        }
	    $azureUserName = $credential.UserName
	    $secureAzurePassword = $credential.Password
	    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAzurePassword)
	    $azurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    if ($azureUserName.StartsWith("{0}\" -f $azureADTenantName))
    {
	    $azureUserName = $azureUserName.Substring($azureUserName.IndexOf("\") + 1);
    }
	
    if (!$azureUserName.EndsWith("@{0}" -f $azureADTenantName))
    {
	    $azureUserName = "{0}@{1}" -f $azureUserName, $azureADTenantName
    }
    #endregion

    $aadLoginScript = "{0}{1}get_aad_access_token.ps1 -azureADTenantName {2} -azureUserName {3} -azurePassword {4}" -f $PSScriptRoot, $dirChar, $azureADTenantName, $azureUserName, $azurePassword
    $azureResponse =  Invoke-Expression -Command $aadLoginScript	
	$token = $azureResponse.access_token;
	return $token;
}

function CreateRequestHeader($graphAccessToken)
{
    return @{
      "Authorization" = "Bearer $graphAccessToken"
      "Content-Type" = "application/json"
    }
}

function CreateAADGroup($azureADTenantName, $groupName, $requestHeader)
{
    Write-Host "Creating AAD Group:" $groupName -ForegroundColor Cyan
    $body = '{
	"odata.metadata": "https://graph.windows.net/sepehrsamieilive.onmicrosoft.com/$metadata#directoryObjects/Microsoft.DirectoryServices.Group/@Element",
	"odata.type": "Microsoft.DirectoryServices.Group",
	"objectType": "Group",
	"objectId": "' + [GUID]::NewGuid() +'",
	"deletionTimestamp": null,
	"description": "' + $groupName + '",
	"dirSyncEnabled": null,
	"displayName": "' + $groupName + '",
	"lastDirSyncTime": null,
	"mail": null,
	"mailNickname": "' + [GUID]::NewGuid() +'",
	"mailEnabled": false,
	"onPremisesDomainName": null,
	"onPremisesNetBiosName": null,
	"onPremisesSamAccountName": null,
	"onPremisesSecurityIdentifier": null,
	"provisioningErrors": [],
	"proxyAddresses": [],
	"securityEnabled": true
}'

    $uri = "https://graph.windows.net/{0}/groups?api-version=1.6" -f $azureADTenantName
    $result = Invoke-RestMethod -Method Post -Headers $requestHeader -Uri $uri -Body $body
}

function FindRegisteredApp($requestHeader, $manifestObj)
{
    $uri = "https://graph.windows.net/{0}/applications?api-version=1.6" -f $azureADTenantName
    $applications = (Invoke-RestMethod -Method Get -Headers $requestheader -Uri $uri)    
    foreach ($app in $applications.value)
    {
        if ($app.appId -eq $manifestObj.appId)
        {
            return $app;            
        }
    }     

    Write-Host "Provided manifest json was not found in registered applications." -ForegroundColor Red
    return $null;
}

function FixSingleMemberArrayConversion($json)
{
	if ($json.GetType().Name -eq "Object[]")
	{
		$json = $json[$json.Length - 1];
	}
	$erroneousStr = '"allowedMemberTypes":"User"';
	$correctStr = '"allowedMemberTypes":["User"]';
	$json = $json.Replace($erroneousStr, $correctStr);
	if (!$json.StartsWith("{"))
	{
		$json = $json.Substring($json.IndexOf("{"));
	}
	
	return $json;
}

function GetAppJson($app, $requestHeader)
{
	$dirChar = "\"
	if ([Environment]::OSVersion.Platform -eq "Unix")
	{
		$dirChar = "/"
	}
	$tmpFileName = Get-Date -Format "yyyy-MM-dd-hh-mm-ss-fff"
    $tmpFilePath = "{0}{1}appmanifest{2}.json" -f $PSScriptRoot, $dirChar, $tmpFileName
    $uri = "https://graph.windows.net/{0}/applications/{1}?api-version=1.6" -f $azureADTenantName, $app.objectId
    Invoke-RestMethod -Method Get -Headers $requestheader -Uri $uri -OutFile $tmpFilePath;
    $appJson = [System.IO.File]::ReadAllText($tmpFilePath);
	Write-S3Object -BucketName $env:AppBucketName -Key $tmpFileName -File $tmpFilePath
    return $appJson
}

function UpdateApp([string] $appJson, $requestHeader)
{
	$aadApp = ConvertFrom-Json -InputObject $appJson;
	$producedApp = ConvertFrom-Json -InputObject $manifestJson;

	$lookup = [System.Collections.HashTable]::new()
	$mendedRoles = [System.Collections.ArrayList]::new()
	$mendedLookup = [System.Collections.HashTable]::new()
	foreach ($role in $aadApp.appRoles)
	{
		if ($role.displayName -eq "msiam_access")
		{
			$mendedRoles.Add($role);
			$mendedLookup.Add($role.id, $role);
		}
		else
		{
			$lookup.Add($role.value, $role)
		}		
	}

	foreach ($role in $producedApp.appRoles)
	{
		if ($role.value -ne $null -and $lookup.ContainsKey($role.value))
		{
			$mendedRoles.Add($lookup[$role.value]);
			$mendedLookup.Add($lookup[$role.value].id, $lookup[$role.value]);
		}
		elseif ($role.displayName -ne "msiam_access")
		{
			$mendedRoles.Add($role);
		}
	}

	#Disabling removed roles to prepare for deletion
	$deletionFound = $false;
	foreach ($role in $aadApp.appRoles)
	{
		if (!$mendedLookup.ContainsKey($role.id))
		{
			$role.isEnabled = $false	
			$deletionFound = $true;
		}
	}
	#Patching aadApp to disable deleted roles
	if ($deletionFound)
	{
		$json = ConvertTo-Json $aadApp -Compress;
		$json = FixSingleMemberArrayConversion($json);
		PatchApp($requestHeader) -app $aadApp -appJson $json
	}

	#Returning final JSON
	
	$aadApp.appRoles = $mendedRoles.ToArray();
	
	$json = ConvertTo-Json $aadApp -Compress;
	
	return $json;
}

function CreateMissingAADGroups($azureADTenantName, $app, $requestHeader)
{
    $uri = "https://graph.windows.net/{0}/groups?api-version=1.6" -f $azureADTenantName
    $groups = Invoke-RestMethod -Method Get -Headers $requestHeader -Uri $uri
    foreach ($role in $app.appRoles)
    {
        $existingGroup = $false
        foreach ($group in $groups.value)
        {
            if ($group.displayName -eq $role.displayName)
            {
                $existingGroup = $true
                Write-Host $group.displayName "already exists" -ForegroundColor Yellow
                break;
            }
        }

        if (!$existingGroup -and $role.allowedMemberTypes -eq "User" -and $role.displayName -ne "msiam_access")
        {
            $groupName = $role.displayName;
            CreateAADGroup($azureADTenantName) -groupName $groupName -requestHeader $requestHeader
        }
        else
        {
            Write-Host "Skipping group " $role.displayName -ForegroundColor Yellow
        }
    }
}

function PatchApp($requestHeader, $app, $appJson)
{
	Write-Host
	
    $uri = "https://graph.windows.net/{0}/applications/{1}?api-version=1.6" -f $azureADTenantName, $app.objectId
    $body = $appJson
	
    Invoke-RestMethod -Method Patch -Headers $requestHeader -Uri $uri -Body $body -Verbose -Debug -ContentType "application/json"
}

######################################################
#Checking parameters
if ([String]::IsNullOrWhiteSpace($azureADTenantName))
{
    Write-Host "Please enter azureADTenantName: "
    $azureADTenantName = Read-Host
}

#Authenticating to AAD
$graphAccessToken = Get-MSGraphToken -azureADTenantName $azureADTenantName -azureUserName $azureUserName -azurePassword $azurePassword
$requestHeader = CreateRequestHeader($graphAccessToken);

#Reading AAD SSO manifest XML file
$manifestObj = ReadManifestJson;

#Obtaining existing application from AAD
$app = FindRegisteredApp($requestHeader) -manifestObj $manifestObj;
$appJson = GetAppJson($app) -requestHeader $requestHeader;

#Updating AAD EApp with JSON output generated from AWS IAM Account/Roles
$appJson = UpdateApp($appJson) -requestHeader $requestHeader;
$appJson = FixSingleMemberArrayConversion($appJson);
Write-Host $appJson

#Creating missing AAD Groups
$groupsApp = ConvertFrom-Json -InputObject $manifestJson
CreateMissingAADGroups($azureADTenantName) -app $groupsApp -requestHeader $requestHeader

#Patching application in AAD
PatchApp($requestHeader) -app $app -appJson $appJson;
Write-Host "Here is a summary of what actions were carried out:"
Write-Host "- Created missing AAD Groups as per the naming convention to map AWS IAM roles to AAD roles;"
Write-Host "- Updated AAD Enterprise App with new Manifest JSON;"
