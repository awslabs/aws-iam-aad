#region defining directory separator character based on environment OS
$dirChar = "\"
if ([Environment]::OSVersion.Platform -eq "Unix")
{
	$dirChar = "/"
}
#endregion

$transcriptPath = "{1}{0}transcript.txt" -f $dirChar, $PSScriptRoot
Start-Transcript $transcriptPath

Write-Host "Environment variables..."
Write-Host "AppBucketName: "$env:AppBucketName
Write-Host "Region: "$env:Region
Write-Host "AppName: "$env:AppName

Write-Host "Getting parameters..."
$azureADTenantName = (Get-SSMParameter -Name $env:AppName".azureADTenantName" -WithDecryption $true -Region $env:Region).Value
$azureUserName = (Get-SSMParameter -Name $env:AppName".azureUserName" -WithDecryption $true -Region $env:Region).Value
$azurePassword = (Get-SSMParameter -Name $env:AppName".azurePassword" -WithDecryption $true -Region $env:Region).Value
$appId = (Get-SSMParameter -Name $env:AppName".appId" -WithDecryption $true -Region $env:Region).Value
$msiam_access_id = (Get-SSMParameter -Name $env:AppName".msiam_access_id" -WithDecryption $true -Region $env:Region).Value
$SAMLMetaDataEntityDescriptorID = (Get-SSMParameter -Name $env:AppName".SAMLMetaDataEntityDescriptorID" -WithDecryption $true -Region $env:Region).Value
$SAMLMetaDataEntityDescriptorEntityID = (Get-SSMParameter -Name $env:AppName".SAMLMetaDataEntityDescriptorEntityID" -WithDecryption $true -Region $env:Region).Value

#region Acquiring list of cross-account roles
$accounts = Get-ORGAccountList

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
$SwitchRoleArnsFilePath = "cross-account-roles-arn-list.json"
$json = "{0}]" -f $json
$res = Set-Content -Value $json -Path $SwitchRoleArnsFilePath
Write-S3Object -BucketName $appName -Key "cross-account-roles-arn-list.json" -File $SwitchRoleArnsFilePath -Force
$message = "{0} was generated using your Amazon Organizations account list. A copy has been placed in application S3 bucket. You can access it on S3 path: s3://{0}/{1}" -f "cross-account-roles-arn-list.json", $appName
Write-Host $message -ForegroundColor Cyan
#endregion
     

Write-Host "Running scripts..."
/docker/aws_iam_to_json.ps1 -appId $appId -msiam_access_id $msiam_access_id -SAMLMetaDataEntityDescriptorID $SAMLMetaDataEntityDescriptorID -SAMLMetaDataEntityDescriptorEntityID $SAMLMetaDataEntityDescriptorEntityID -SwitchRoleArnsFileJson $SwitchRoleArnsFilePath -NamingConvention $env:NamingConvention | /docker/aad_eapp_update.ps1 -azureADTenantName $azureADTenantName -azureUserName $azureUserName -azurePassword $azurePassword

Stop-Transcript

#Writing logs to S3 bucket
if ($env:SaveTranscriptToS3 -eq "true" -or $env:SaveTranscriptToS3 -eq "True" -or $env:SaveTranscriptToS3 -eq "TRUE")
{
    Write-S3Object -BucketName $env:AppBucketName -Key "transcript.txt" -File $transcriptPath -Force
}