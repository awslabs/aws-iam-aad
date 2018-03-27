<#Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at
  
      http://www.apache.org/licenses/LICENSE-2.0
  
  or in the "license" file accompanying this file. This file is distributed 
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
  express or implied. See the License for the specific language governing 
  permissions and limitations under the License.#>

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

$existingParameters = Get-SSMParameterList -Region $env:Region
$arnList = [System.Collections.ArrayList]::new()
foreach ($p in $existingParameters)
{
	$pattern = "{0}.arn*" -f $env:AppName
    if ($p.Name -Like $pattern)
    {
		$par = Get-SSMParameter -Name $p.Name -WithDecryption $true -Region $env:Region
        $arnList.Add($par.Value)
    }
}
$arnListJson = ConvertTo-Json -InputObject $arnList;
$arnListPath = "{0}{1}arnList.json" -f $PSScriptRoot, $dirChar
[System.IO.File]::WriteAllText($arnListPath, $arnListJson);        

Write-Host "Running scripts..."
/docker/aws_iam_to_json.ps1 -appId $appId -msiam_access_id $msiam_access_id -SAMLMetaDataEntityDescriptorID $SAMLMetaDataEntityDescriptorID -SAMLMetaDataEntityDescriptorEntityID $SAMLMetaDataEntityDescriptorEntityID -SwitchRoleArnsFileJson $arnListPath -NamingConvention $env:NamingConvention | /docker/aad_eapp_update.ps1 -azureADTenantName $azureADTenantName -azureUserName $azureUserName -azurePassword $azurePassword

Stop-Transcript

#Writing logs to S3 bucket
if ($env:SaveTranscriptToS3 -eq "true" -or $env:SaveTranscriptToS3 -eq "True" -or $env:SaveTranscriptToS3 -eq "TRUE")
{
    Write-S3Object -BucketName $env:AppBucketName -Key "transcript.txt" -File $transcriptPath -Force
}