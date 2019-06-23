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
    [string] $appName = "aad_aws_sso",
	[Parameter(Mandatory=$true)]	
    [string] $kmsKeyId, 
    [string] $NamingConvention = "AWS {0} - {1}", 
    [string] $Region = "us-east-1"
)

Import-Module -Name AWSPowerShell.NetCore

#region defining directory separator character based on environment OS
$dirChar = "\"
if ([Environment]::OSVersion.Platform -eq "Unix")
{
	$dirChar = "/"
}
#endregion

#region Finding parameter file names
$jsonFiles = Get-ChildItem -Path $PSScriptRoot -Name *.json
if ($jsonFiles.Count -eq 0)
{
	Write-Host "Expected to find Manifest JSON file in setup directory. No json files were found. Terminating setup unsuccessfully."
	Exit 1;
}
elseif ($jsonFiles.Count -gt 1)
{
	Write-Host "More than one JSON file found in setup directory. Please enter the file name for Manifest JSON:"
	$ManifestJsonPath = Read-Host
}
else
{
	$ManifestJsonPath = $jsonFiles
}

$xmlFiles = Get-ChildItem -Path $PSScriptRoot -Name *.xml
if ($xmlFiles.Count -eq 0)
{
	Write-Host "Expected to find SAML Certificate Metadata XML file in setup directory. No XML files were found. Terminating setup unsuccessfully."
	Exit 1;
}
elseif ($xmlFiles.Count -gt 1)
{
	Write-Host "More than one XML file found in setup directory. Please enter the file name for Manifest SAML Certificate Metadata XML:"
	$SAMLCertificateFilePath = Read-Host
}
else
{
	$SAMLCertificateFilePath = $xmlFiles
}
#endregion

#region Verifying Azure credentials
    #region Validating parameters
    if ([System.String]::IsNullOrWhiteSpace($azureUserName) -or [System.String]::IsNullOrWhiteSpace($azurePassword))
    {
	    $message = "Please enter your Azure credentials. Your Azure user must be on Azure tenant {0}, and be assigned as owner of your AWS SSO app within this AAD tenant." -f $azureADTenantName	    
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

    #region Testing credentials
    Write-Host "Testing provided Azure credentials..."
    $aadLoginScript = "{0}{1}get_aad_access_token.ps1 -azureADTenantName {2} -azureUserName {3} -azurePassword {4}" -f $PSScriptRoot, $dirChar, $azureADTenantName, $azureUserName, $azurePassword
	try
	{
		$azureResponse =  Invoke-Expression -Command $aadLoginScript
	}
	catch
	{
		if ($_.Exception.Message.contains("AADSTS70002"))
		{
			Write-Host "Invalid Azure AD credentials. Login failed while testing provided credentials." -ForegroundColor Red
		}
		elseif ($_.Exception.Message.contains("AADSTS70002"))
		{
			Write-Host "Invalid AAD tenant name. Login failed while testing provided credentials." -ForegroundColor Red
		}
		else
		{
			Write-Host $_.Exception.Message -ForegroundColor Red
		}
		
		Write-Host "Encountered error while validating parameters. Aborting execution. Please re-run the script either through command line, or by opening a new session."
		Exit 1;
	}
    Write-Host $azureResponse -ForegroundColor Yellow
    #endregion
#endregion

#region Acquiring app manifest json values
if (![System.IO.File]::Exists($ManifestJsonPath) -and [Environment]::OSVersion.Platform -eq "Unix" -and $PSScriptRoot -eq "/home/ec2-user/scripts/setup")
{
	$ManifestJsonPath = "{0}/{1}" -f $PSScriptRoot, $ManifestJsonPath
}
$json = [System.IO.File]::ReadAllText($ManifestJsonPath);
$manifestObj = ConvertFrom-Json -InputObject $json;
$appId = $manifestObj.appId;
foreach ($role in $manifestObj.appRoles)
{
	if ($role.displayName -eq "msiam_access")
	{
        $msiam_access_id = $role.id;
        break;
	}
}
#endregion

#region Acquiring SAML Metadata attributes
if (![System.IO.File]::Exists($SAMLMetadataFilePath) -and [Environment]::OSVersion.Platform -eq "Unix" -and $PSScriptRoot -eq "/home/ec2-user/scripts/setup")
{
	$SAMLCertificateFilePath = "{0}/{1}" -f $PSScriptRoot, $SAMLCertificateFilePath
}
[xml]$SAMLCertificate = Get-Content $SAMLCertificateFilePath
$SAMLMetaDataEntityDescriptorID = $SAMLCertificate.EntityDescriptor.ID
$SAMLMetaDataEntityDescriptorEntityID = $SAMLCertificate.EntityDescriptor.entityID
#endregion

#region Getting swtich role arn values
Write-Host "Using Amazon Organizations to generate cross-account roles ARN values..."
$accounts = Get-ORGAccountList
Write-Host "Found " $accounts.Length "accounts in your organization."
#Get root account identity
$identity = Get-STSCallerIdentity
$arns = New-Object string[] ($accounts.Length - 1)
$count = 0;
$json = "["
foreach ($a in $accounts)
{
	#include only accounts other than root account
	if ($a.Id -ne $identity.Account)
	{
		if (!$json.EndsWith('['))
		{
			$json = "{0}," -f $json
		}
		$roleArn = "arn:aws:iam::{0}:role/AWS_IAM_AAD_UpdateTask_CrossAccountRole" -f $a.Id
		$arns[$count++] = $roleArn
		$json = "{0}`"{1}`"" -f $json, $roleArn			
	}
}	
$json = "{0}]" -f $json
$SwitchRoleArnsFilePath = "{0}{1}cross-account-roles-arn-list.json" -f $PSScriptRoot, $dirChar
$res = Set-Content -Value $json -Path $SwitchRoleArnsFilePath
Write-S3Object -BucketName $appName -Key "cross-account-roles-arn-list.json" -File $SwitchRoleArnsFilePath -Force
$message = "{0} was generated using your Amazon Organizations account list. A copy has been placed in application S3 bucket. You can access it on S3 path: s3://{0}/{1}" -f "cross-account-roles-arn-list.json", $appName
Write-Host $message -ForegroundColor Cyan
#endregion

#region Creating SSM Parameters
Write-SSMParameter -Name $appName".azureADTenantName" -Value $azureADTenantName -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
#Write-SSMParameter -Name $appName".azureUserName" -Value $azureUserName -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
#Write-SSMParameter -Name $appName".azurePassword" -Value $azurePassword -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
Update-SECSecret -SecretId $appName".azureCredentials" -SecretString "{`"AzureUser`":`"$azureUserName`",`"AzurePassword`":`"$azurePassword`"}" -KmsKeyId $kmsKeyId -Region $Region

Write-SSMParameter -Name $appName".appId" -Value $appId -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
Write-SSMParameter -Name $appName".msiam_access_id" -Value $msiam_access_id -KeyId $kmsKeyId  -Type SecureString -Region $Region -Overwrite $true

Write-SSMParameter -Name $appName".SAMLMetaDataEntityDescriptorID" -Value $SAMLMetaDataEntityDescriptorID -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
Write-SSMParameter -Name $appName".SAMLMetaDataEntityDescriptorEntityID" -Value $SAMLMetaDataEntityDescriptorEntityID -KeyId $kmsKeyId -Type SecureString -Region $Region -Overwrite $true
#endregion

#region Creating Docker image
$DockerPath = "{0}/../docker/" -f $PSScriptRoot
$ECRLogin = Get-ECRLoginCommand
(Get-ECRRepository).foreach{ if ($_.RepositoryName -eq $appName) { $Repository = $_; } }

$dockerTagCommand = "docker tag {0}:latest {1}:latest" -f $appName, $Repository.RepositoryUri
$dockerPushCommand = "docker push {0}:latest" -f $Repository.RepositoryUri
$dockerBuildCommand = "docker build {0} -t {1}:latest" -f $DockerPath, $appName

Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $ECRLogin.Command
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $dockerBuildCommand
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $dockerTagCommand
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $dockerPushCommand
sudo chmod +x /home/ec2-user/scripts/setup/docker-push.sh
sudo /home/ec2-user/scripts/setup/docker-push.sh
#endregion

#region Deploying SAML federation roles in target AWS accounts
$SAMLRolesCfnPath = "{0}/saml-roles.json" -f $PSScriptRoot
if ([System.IO.File]::Exists($SAMLRolesCfnPath))
{
	#Replacing MetadataDocument with actual SAML certificate metadata
	$SAMLCertificateStr = Get-Content $SAMLCertificateFilePath
	$SAMLCertificateStr = $SAMLCertificateStr.Replace("`"", "\`"")
	$SAMLRolesCfn = [System.IO.File]::ReadAllText($SAMLRolesCfnPath)
    $SAMLRolesCfn = ([System.String]$SAMLRolesCfn).Replace("<MetadataDocument>", $SAMLCertificateStr)
	Set-Content -Path $SAMLRolesCfnPath -Value $SAMLRolesCfn	
	
		#region Ascertaining account id of target accounts
		$StackSetInstanceAccounts = New-Object string[] $arns.Count
		$accounts = Get-ORGAccountList
		$count = 0;
		$AccountsStr = ""
		foreach ($a in $accounts)
		{
			#Uncomment to include only accounts other than root account
			#if ($a.Id -ne $identity.Account)
			{
				$StackSetInstanceAccounts[$count++] = $a.Id		
				if ([System.String]::IsNullOrWhiteSpace($AccountsStr))
				{
					$AccountsStr = $a.Id
				}
				else
				{
					$AccountsStr = "{0},{1}" -f $AccountsStr, $a.Id
				}
			}
		}
		$AccountsStrPath = "{0}/accounts.txt" -f $PSScriptRoot
		Set-Content -Path $AccountsStrPath -Value $AccountsStr
		#endregion
	
	#Saving the final StackSet template in application S3 bucket for future use.
	Write-S3Object -BucketName $appName -Key "saml-roles-cfn.json" -File $SAMLRolesCfnPath -Force
	Write-S3Object -BucketName $appName -Key "accounts.txt" -File $AccountsStrPath -Force
	
	$message = "StackSet template is stored in S3 bucket {0}/saml-roles-cfn.json. Would you like to deploy it now?<y/n>" -f $appName
	Write-Host $message -ForegroundColor Cyan
	$prmpt = Read-Host
	if ($prmpt -eq "y")
	{
		#Deploying StackSet through CloudFormation
		$Capabilities = New-Object string[] 2
		$Capabilities[0] = "CAPABILITY_NAMED_IAM"
		$Capabilities[1] = "CAPABILITY_IAM"
		New-CFNStackSet -StackSetName $appName -TemplateBody $SAMLRolesCfn -Capability $Capabilities
		Get-CFNStackSetList
		$StackSetInstanceRegions = New-Object string[] 1
		$StackSetInstanceRegions[0] = $Region
		
		New-CFNStackInstance -StackSetName $appName -StackInstanceRegion $StackSetInstanceRegions -Account $StackSetInstanceAccounts
	}
}
#endregion

Write-Host "Completed running setup.ps1 script. SAML federation synchronization task is now configured. If you did not receive any errors during setup, synchronization task can be verified at provided frequency periods."