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
    [string] $ManifestJsonPath, 
    [Parameter(Mandatory=$true)]
    [string] $SAMLCertificateFilePath, 
    [Parameter(Mandatory=$true)]
    [string] $SwitchRoleArnsFilePath,
    [Parameter(Mandatory=$true)]
    [string] $azureADTenantName,
    [string] $azureUserName, 
    [string] $azurePassword, 
    [string] $appName = "aad_aws_sso", 
    [string] $kmsKeyId, 
    [string] $NamingConvention = "AWS {0} - {1}", 
    [string] $Region = "us-east-1"
)

#region defining directory separator character based on environment OS
$dirChar = "\"
if ([Environment]::OSVersion.Platform -eq "Unix")
{
	$dirChar = "/"
}
#endregion

#region Verifying Azure credentials
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

    #region Testing credentials
    Write-Host "Testing provided Azure credentials..."
    $aadLoginScript = "{0}{1}get_aad_access_token.ps1 -azureADTenantName {2} -azureUserName {3} -azurePassword {4}" -f $PSScriptRoot, $dirChar, $azureADTenantName, $azureUserName, $azurePassword
    $azureResponse =  Invoke-Expression -Command $aadLoginScript
    Write-Host $azureResponse -ForegroundColor Yellow
    #endregion
#endregion

#region Verifying KMS key ID
try
{
    $kmsKey = Get-KMSKey -KeyId $kmsKeyId -Region $Region
}
catch
{
    Write-Host "You have not provided a KMS key or the key id you have provided does not exist. Would you like to create a new key now? If you select no, the default KMS key for SSM will be used. (enter <y> to create a new key)"
    $createNewKey = Read-Host
    if ($createNewKey -eq "y" -or $createNewKey -eq "Y")
    {
        $kmsKeyId = (New-KMSKey -Description $appName"_secrets_key" -Region $Region).KeyId
    }
    else
    {
        Write-Host "Default SSM key will be used for encryption of secrets."
        $kmsKeyId = "alias/aws/ssm"
    }
}
#endregion

###############################################################################################################

#region Finding IAM Role for ECS Fargate task
$roleName = "{0}_ECS_Role" -f $appName
$role = Get-IAMRole -RoleName $roleName
#endregion

#region Ascertaining account id
$keyArn = (Get-KMSKey -KeyId $kmsKeyId).Arn
$keyArnSegments = ([System.String]$keyArn).Split(':')
$accountId = $keyArnSegments[4]
#endregion

#region Creating policy document to get AWS Parameter Store secrets

    #region generating secret access policy document
    $secretAccessPolicyTemplatePath = "{0}{1}aad-sso-secret-access.json" -f $PSScriptRoot, $dirChar

    $secretAccessPolicy = [System.IO.File]::ReadAllText($secretAccessPolicyTemplatePath)
    $secretAccessPolicy = ([System.String]$secretAccessPolicy).Replace("<key-id-aad_aws_sso-key>", $kmsKeyId)
    $secretAccessPolicy = ([System.String]$secretAccessPolicy).Replace("<account-id>", $accountId)
	$secretAccessPolicy = ([System.String]$secretAccessPolicy).Replace("<app_name>", $appName)
    #endregion

$policyArn = "arn:aws:iam::{0}:policy/{1}" -f $accountId, $appName

$policy = $null
try
{
	$policy = Get-IAMPolicy -PolicyArn $policyArn
}
catch
{
	Write-Host "Creating policy to grant access to SSM Parameter Store..."
}
if ($policy -ne $null)
{
	if ($role -ne $null)
	{
		$attachedPolicies = Get-IAMAttachedRolePolicyList -RoleName $roleName
		foreach ($p in $attachedPolicies)
		{
			if ($p.PolicyArn -eq $policyArn)
			{
				Unregister-IAMRolePolicy -RoleName $roleName -PolicyArn $p.PolicyArn
			}			
		}
	}
    Remove-IAMPolicy -PolicyArn $policyArn
}

New-IAMPolicy -PolicyName $appName -PolicyDocument $secretAccessPolicy
Register-IAMRolePolicy -RoleName $roleName -PolicyArn $policyArn
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
if (![System.IO.File]::Exists($SwitchRoleArnsFilePath) -and [Environment]::OSVersion.Platform -eq "Unix" -and $PSScriptRoot -eq "/home/ec2-user/scripts/setup")
{
	$SwitchRoleArnsFilePath = "{0}/{1}" -f $PSScriptRoot, $SwitchRoleArnsFilePath
}
$json = [System.IO.File]::ReadAllText($SwitchRoleArnsFilePath);
$arns = ConvertFrom-Json -InputObject $json;
#endregion

#region Removing existing SSM parameters
$existingParameters = Get-SSMParameterList -Region $Region
foreach ($p in $existingParameters)
{
    if ($p.Name -Like "$appName*")
    {
        Remove-SSMParameter -Name $p.Name -Force -Region $Region
    }
}
#endregion

#region Creating SSM Parameters
Write-SSMParameter -Name $appName".azureADTenantName" -Value $azureADTenantName -KeyId $kmsKeyId -Type SecureString -Region $Region
Write-SSMParameter -Name $appName".azureUserName" -Value $azureUserName -KeyId $kmsKeyId -Type SecureString -Region $Region
Write-SSMParameter -Name $appName".azurePassword" -Value $azurePassword -KeyId $kmsKeyId -Type SecureString -Region $Region

Write-SSMParameter -Name $appName".appId" -Value $appId -KeyId $kmsKeyId -Type SecureString -Region $Region
Write-SSMParameter -Name $appName".msiam_access_id" -Value $msiam_access_id -KeyId $kmsKeyId  -Type SecureString -Region $Region

Write-SSMParameter -Name $appName".SAMLMetaDataEntityDescriptorID" -Value $SAMLMetaDataEntityDescriptorID -KeyId $kmsKeyId -Type SecureString -Region $Region
Write-SSMParameter -Name $appName".SAMLMetaDataEntityDescriptorEntityID" -Value $SAMLMetaDataEntityDescriptorEntityID -KeyId $kmsKeyId -Type SecureString -Region $Region

for ($c = 0; $c -lt $arns.Count; $c++)
{
    Write-SSMParameter -Name $appName".arn"$c -Value $arns[$c] -KeyId $kmsKeyId -Type SecureString -Region $Region
}
#endregion

#region Creating Docker image
$DockerPath = "{0}/../docker/" -f $PSScriptRoot
$Repository = New-ECRRepository -RepositoryName $appName -Region $Region
$ECRLogin = Get-ECRLoginCommand
$ECRLogin.Command

$dockerTagCommand = "docker tag {0}:latest {1}:latest" -f $appName, $Repository.RepositoryUri
$dockerPushCommand = "docker push {0}:latest" -f $Repository.RepositoryUri

Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $ECRLogin.Command
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value "docker build ${DockerPath} -t ${appName}:latest"
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $dockerTagCommand
Add-Content -Path "/home/ec2-user/scripts/setup/docker-push.sh" -Value $dockerPushCommand
sudo chmod +x /home/ec2-user/scripts/setup/docker-push.sh
sudo /home/ec2-user/scripts/setup/docker-push.sh
#endregion

Write-Host "Completed running setup.ps1 script. SAML federation synchronization task is now configured. If you did not receive any errors during setup, synchronization task can be verified at provided frequency periods."