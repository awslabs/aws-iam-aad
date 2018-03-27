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
    [Parameter(Mandatory=$true)]
    [string] $azureUserName, 
    [Parameter(Mandatory=$true)]
    [string] $azurePassword
)


$AzureADAuthority = "https://login.microsoftonline.com/$azureADTenantName/oauth2/token"
$resourceURL = "https://graph.windows.net/"
$powerShellClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$params = @{
		"resource" = $resourceURL;
		"client_id" = $powerShellClientId;
		"grant_type" = "password";
		"username" = $azureUserName;
		"password" = $azurePassword;
		"scope" = "openid";
	}	
$azureResponse = Invoke-RestMethod -Method Post -Uri $AzureADAuthority -Body $params -Verbose -Debug
return $azureResponse;