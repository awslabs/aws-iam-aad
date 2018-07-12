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
    [string] $appId, 
    [Parameter(Mandatory=$true)]
    [string] $msiam_access_id, 
    [Parameter(Mandatory=$true)]
    [string] $SAMLMetaDataEntityDescriptorID, 
    [Parameter(Mandatory=$true)]
    [string] $SAMLMetaDataEntityDescriptorEntityID,
    [string] $SwitchRoleArnsFileJson, 
    [string] $NamingConvention = "AWS {0} - {1}", 
    [string] $OutFile
)

#region defining directory separator character based on environment OS
$dirChar = "\"
if ([Environment]::OSVersion.Platform -eq "Unix")
{
	$dirChar = "/"
}
#endregion

function SwitchAccount()
{
    if (![String]::IsNullOrWhiteSpace($SwitchRoleArnsFileJson))
    {
        $json = [System.IO.File]::ReadAllText($SwitchRoleArnsFileJson);
        $arnList = ConvertFrom-Json -InputObject $json;        
		$credList = [System.Collections.ArrayList]::new();
        $arnList.ForEach{
            $roleArn = $_;
			$creds = (Use-STSRole -RoleArn $roleArn -RoleSessionName "Setting_up_AAD_SSO_to_AWS_Console").Credentials
			$count = $credList.Add($creds);
		}
		
		ProcessAccount
		$credList.ForEach{
			$creds = $_;
			Set-AWSCredential -Credential $creds
			ProcessAccount
		}
    }
}

#Find SAML Provider with given Metadata document
function FindSAMLProviderArn()
{
	$samlProviders = Get-IAMSAMLProviders
	$spArn = [system.collections.arraylist]::new();
	foreach ($sprovider in $samlProviders)
	{        
		$provider = Get-IAMSAMLProvider -SAMLProviderArn $sprovider.Arn
		$metadata = [xml]$provider.SAMLMetadataDocument
		if (($metadata.EntityDescriptor.ID -eq $SAMLMetaDataEntityDescriptorID) -and ($metadata.EntityDescriptor.entityID -eq $SAMLMetaDataEntityDescriptorEntityID))
		{
			$count = $spArn.Add($sprovider.Arn);
		}
	}

	return $spArn.ToArray();
}

#Find IAM Roles associated with a SAML provider
function FindFederatedRoles($samlProviderArn)
{
	$arnList = [System.Collections.ArrayList]::new();
	if ($samlProviderArn -ne [string]::Empty)
	{        
		foreach ($role in Get-IAMRoles)
		{
			if ($role.AssumeRolePolicyDocument -Like "*SAML*")
			{
				$policy = [System.Net.WebUtility]::UrlDecode($role.AssumeRolePolicyDocument)
				$expected = "*{0}*" -f $samlProviderArn
				if ($policy -like $expected)
				{
					$combinedArn = "{0},{1}" -f $role.Arn, $samlProviderArn
					$count = $arnList.Add($combinedArn);
				}
			}
		}        
	}
	return $arnList;
}

function ReadManifestJson()
{
	$json = [System.IO.File]::ReadAllText($OutFile);
	$manifestObj = ConvertFrom-Json -InputObject $json;
	return $manifestObj;
}

function AddAppRoleToManifest([System.Collections.ArrayList] $appRoles, $arn)
{
    $result = $null;
	foreach ($role in $appRoles)
	{
		if ($role.value -eq $arn)
		{			
			Write-Host "Skipping " $arn -ForegroundColor Green
			$result = $appRoles;
            break;
		}
	}
    
    if ($result -eq $null)
    {
	    Write-Host "Adding " $arn -ForegroundColor Green
	    $json = ComposeManifestJson($arn);                    
	    $role = ConvertFrom-Json($json);
	    $count = $appRoles.Add($role);

	    $result = $appRoles;
    }
	return $result
}

#Naming convention is defined here
function ExtractSampleGroupName($arn)
{
	$account = "";
	#Uncomment below line if you want to use account alias instead of account number. Account number is preferred because it is fixed. But alias could change at any time in future.
	#$account = Get-IAMAccountAlias
	if ([string]::IsNullOrWhiteSpace($account))
	{
		$account = $arn.SubString($arn.IndexOf("::") + 2);
		$account = $account.SubString(0, $account.IndexOf(":"));
	}
	$role = $arn.SubString($arn.IndexOf("/") + 1);
	$role = $role.SubString(0, $role.IndexOf(","));

	#This is the actual naming convention
	$sampleGroupName = $NamingConvention -f $account, $role

	return $sampleGroupName;
}

function ComposeManifestJson($arn)
{
	$sampleGroupName = ExtractSampleGroupName($arn);

	$strWriter = [System.IO.StringWriter]::new();
	$strWriter.WriteLine("{");
	$strWriter.WriteLine('  "allowedMemberTypes": [');
	$strWriter.WriteLine('    "User"');
	$strWriter.WriteLine('  ],');
	$strWriter.WriteLine('  "displayName": "{0}",' -f $sampleGroupName);
	$strWriter.WriteLine('  "id": "{0}",' -f [guid]::NewGuid());
	$strWriter.WriteLine('  "isEnabled": true,');
	$strWriter.WriteLine('  "description": "{0}",' -f $sampleGroupName);
	$strWriter.WriteLine('  "value": "{0}"' -f $arn);
	$strWriter.WriteLine('}');
	$json = $strWriter.ToString();

	return $json;
}

function TraverseRoles($samlProviderArn, [System.Collections.ArrayList] $appRoles)
{
	$arnList = FindFederatedRoles($samlProviderArn);

	foreach ($arn in $arnList)
	{
		if (([string]$arn).Length -gt 24)
		{
			$appRoles = AddAppRoleToManifest($appRoles) -arn $arn
		}
	}

	return $appRoles;
}   

function FixSingleMemberArrayConversion($json)
{
	$erroneousStr = '"allowedMemberTypes":"User"';
	$correctStr = '"allowedMemberTypes":["User"]';
	$json = $json.Replace($erroneousStr, $correctStr);
	return $json;
}

function PrintOutput($manifestObj)
{
	$json = ConvertTo-Json -InputObject $manifestObj -Compress;
	$json = FixSingleMemberArrayConversion($json)
	if (![String]::IsNullOrWhiteSpace($OutFile))
	{
		[System.IO.File]::WriteAllText($OutFile, $json);                        
	}                    
}

function ProcessAccount()
{
	$manifestObj = ReadManifestJson;
	$appRoles = [System.Collections.ArrayList]::new();
	$count = $appRoles.AddRange($manifestObj.appRoles);

	$samlProviderArnList = FindSAMLProviderArn;
	$newAppRoles = [System.Collections.ArrayList]::new();
	$samlProviderArnList.ForEach{
		$samlProviderArn = $_;
		$appRoles = TraverseRoles($samlProviderArn) -appRoles $appRoles 
	}
	foreach ($ar in $appRoles)
		{
			if ($ar.allowedMemberTypes -eq "User")
			{
				$count = $newAppRoles.Add($ar);
			}
		}
	$manifestObj.appRoles = $newAppRoles.ToArray();

	PrintOutput($manifestObj);  
}

function PrepareCleanSlateOnOutFile()
{
    $manifestTemplatePath = "{0}{1}manifest_template.json" -f $PSScriptRoot, $dirChar
	[System.IO.File]::Copy($manifestTemplatePath, $OutFile, $true); 
	$json = [System.IO.File]::ReadAllText($manifestTemplatePath);
	$manifestObj = ConvertFrom-Json -InputObject $json;
    $manifestObj.appId = $appId
	foreach ($role in $manifestObj.appRoles)
	{
		if ($role.displayName -eq "msiam_access")
		{
            $role.id = $msiam_access_id;
			$manifestObj.appRoles = @($role)
			$json = ConvertTo-Json -InputObject $manifestObj -Compress
			[System.IO.File]::WriteAllText($OutFile, $json);
		}
	}
}

function TraverseAccounts()
{    
    PrepareCleanSlateOnOutFile
    SwitchAccount
    $outputjson = [System.IO.File]::ReadAllText($OutFile);

    $message = "JSON output is copied to {0}" -f $OutFile
    Write-Host $message;

	return $outputjson;
}

########################################################################

#Checking parameters
if (![String]::IsNullOrWhiteSpace($OutFile))
{
    if ([System.IO.File]::Exists($OutFile))
    {
        Write-Host "Warning! Target output file already exists. If you proceed, the file will be overwritten. Press <ENTER> continue..." -ForegroundColor Yellow
        Read-Host
        Write-Host "Processing. Please wait..." -ForegroundColor Green
        #[System.IO.File]::Delete($OutFile);
    }
}
else
{
	if ([Environment]::OSVersion.Platform -eq "Unix")
	{
		$OutFile = "{0}/output.json" -f $PSScriptRoot
	}
	else
	{
		$OutFile = "{0}\output.json" -f $PSScriptRoot
	}
    Write-Host "Processing. Please wait..." -ForegroundColor Green
}
######################################################

#Generate AAD EApp manifest JSON from AWS IAM Account/Roles
return TraverseAccounts;