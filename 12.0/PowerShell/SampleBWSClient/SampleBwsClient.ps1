<#
# Copyright (c) 2014 BlackBerry.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#>

<#  
# 1.) Generate proxy files for BWS and BWSUtil web services.
# a.) Navigate to the bin folder for your Microsoft SDK via cmd prompt.  E.g  c:\Program Files\Microsoft SDKs\Windows\v7.0A\bin
# b.) Type:  wsdl /sharetypes /o:<proxy_path>\<proxy_file_name> https://<servername>:<port>/enterprise/admin/ws?wsdl https://<server_name>:<port>/enterprise/admin/util/ws?wsdl
# Example  wsdl /sharetypes /o:C:\Temp\BWSServices.cs https://server1.net:18084/enterprise/admin/ws?wsdl https://server1.net:18084/enterprise/admin/util/ws?wsdl
#
#2.)  Import the BWS proxy files into C# project and compile into a DLL.
#a.)  Within Visual Studio create a new C# project and select Class Library and provide a name.  E.g. BWSProxy
#b.)  In solution explorer pane, right-click the project and select Add -> Existing Item.
#c.)  Navigate to the proxy files you have generated and click "Add".
#d.)  Delete the class file that was originally created and left with the BWS proxy file you imported.
#f.)  Compile into DLL.
#>

#Load BWS API DLL
Add-Type -Path "<path to BWS.dll>";

<#
# SampleBwsClient.ps1
#
# A program that demonstrates PowerShell integration to BlackBerry Web Services (BWS) for Enterprise Administration APIs.
#
# This sample program demonstrates how to use BWS.getUsers() and BWS.getUserDetails() API's in order to display information
# such as email address, device PIN and device model.
#>

<#
# All BWS APIs are passed a request object (which contains metadata and parameters) and return a response object (which
# contains metadata, return status and possibly results). The request metadata defines information (clientVersion, locale,
# orgUid) common to all BWS APIs. The response metadata defines information (executionTime, requestUid) about this
# particular API call. A few BWS API calls (BWSUtil.*) do not require authentication (credentials) because they are only
# requesting information required to perform other requests.
# 
# This program has a Setup() method that shows how to create the web service objects needed to perform BWS calls. A method
# like this will be needed in all PowerShell scripts that integrate to BWS. This program also has a
# GetUsersAndDisplaySomeUserData() method, that is demonstrating some functionality specific to this script.
# 
# For more information about BlackBerry Web Services, see
# http://docs.blackberry.com/en/admin/categories/?userType=2&category=BlackBerry+Web+Services
#>

#Create and intitialize the request metadata object.
$Metadata = New-Object RequestMetadata;
# Use the version of the BWS.DLL used to generate the proxy, not the version of the server.
$Metadata.clientVersion = "12.0.0";
$Metadata.locale = "en_US";
$Metadata.organizationUid = "0";

#Prompt the user for the BWS hostname, username and password.
$BWSHostName = Read-Host 'Enter BWSHostName:Port (E.g. BWS.host.name:18084) ';
$UserName = Read-Host 'Enter Username ';
$Password = Read-Host 'Enter Password ';

$bwsService = New-Object bwsService;
$bwsUtilService = New-Object bwsUtilService;

<#
# <summary>
#  Initialize BWS and BWSUtil services
# </summary>
# <returns>Returns true when the setup is successful, and false otherwise.</returns>
#>
function Setup()
{
	$methodName = "Setup()";
	Write-Host([string]::Format("Entering {0}...", $methodName));
	$returnValue = $false;
	
	#Url that point to the web service for all calls.
	$bwsService.Url = "https://" + $BWSHostName + "/enterprise/admin/ws";
	$bwsUtilService.Url = "https://" + $BWSHostName + "/enterprise/admin/util/ws";
	
	#set the connection timeout to 60 seconds.
	$bwsService.Timeout = 60000;
	$bwsUtilService.Timeout = 60000;
	
	$authenticator = New-Object Authenticator;
	$authenticator = GetAuthenticator("BlackBerry Administration Service");
	
	if ($authenticator -ne $null)
	{
		$encodedUserName = GetEncodedUserName $UserName $authenticator;
		if (![string]::IsNullOrEmpty($encodedUserName))
		{
			#Set the HTTP basic authentication on the BWS service.
			#BWSUtilService is a utility web service that does not require authentication.

			$bwsService.Credentials = New-Object System.Net.NetworkCredential($encodedUserName, $Password);
			
			#Send an HTTP Authorization header with requests after authentication
			#has taken place.
			
			$bwsService.PreAuthenticate = $true;
			$returnValue = $true;
		}
		else
		{
			Write-Host("'encodedUsername' is null or empty");
		}
	}
	else
	{
		Write-Host("'authenticator' is null");
	}
	Write-Host([string]::Format("...exiting {0} with value '{1}'", $methodName, $returnValue));
	return $returnValue;
}

<# 
<summary>
# Get the authenticator object for the authenticator name.
# </summary>
# <param name = "authenticatorName">A string containing the name of the desired authenticator.</param >
#<returns>Returns the requested authenticator if it is found, and null otherwise.</returns>
#>
function GetAuthenticator($authenticatorName)
{
	$methodName = "GetAuthenticator()";
	Write-Host([string]::Format("Entering {0}...", $methodName));
	
	$returnValue = New-Object Authenticator;
	$returnValue = $null;
	$request = New-Object GetAuthenticatorsRequest;
	$request.metadata = $Metadata;
	
	$response = New-Object GetAuthenticatorsResponse;
	$response = $null;
	
	$bwsApiName = "bwsUtilService.getAuthenticators()";
	Write-Host([string]::Format("Entering {0}...", $bwsApiName));
	$response = $bwsUtilService.getAuthenticators($request);
	Write-Host([string]::Format("{0} returned {1}",$bwsApiName, $response.returnStatus.code.ToString()));
		
	if ($response.returnStatus.code.Equals("SUCCESS"))
	{
			$authenticator = New-Object Authenticator;
			foreach ($authenticator in $response.authenticators)
			{
				if ($authenticator.name -eq $authenticatorName)
				{
					$returnValue = $authenticator;
					break;
				}
			}
			if ($returnValue -eq $null)
			{
				Write-Host([string]::Format("{0} not found", $AuthenticatorName));
			}
	}
	else
	{
		Write-Host([string]::Format("Error Message: {0}", $response.returnStatus.message));
	}
	Write-Host([string]::Format("...exiting {0} with value {1}", $methodName, $response.returnStatus.code.ToString()));
	return $returnValue;
}

<#
# <summary>
# Get the encoded username required to authenticate user to BWS.
# </summary>
# <param name = "username">A string containing the username to encode.</param >
# <param name = "authenticator">The authenticator.</param >
# <returns>Returns a string containing the encoded username if successful, and a null message string
# otherwise.</returns>
#>
function GetEncodedUserName ($username, $authenticator)
{
	$methodName = "GetEncodedUserName()";
	Write-Host([string]::Format("Entering {0}...", $methodName));
	$returnValue = $null;
	
	$request = New-Object GetEncodedUsernameRequest;
	$response = New-Object GetEncodedUsernameResponse;
	$request.metadata = $Metadata;
	$request.username = $username;
	$request.orgUid = $Metadata.organizationUid;
	$request.authenticator = $authenticator;
	
	$credentialType = New-Object CredentialType;
	$credentialType.PASSWORD = $true;
	$credentialType.value = "PASSWORD";
	$request.credentialType = $credentialType;
	
	$bwsApiName = "bwsUtilService.getEncodedUsername()"
	Write-Host([string]::Format("Entering {0}...", $bwsApiName));
	$response = $bwsUtilService.getEncodedUsername($request);
	Write-Host([string]::Format("{0} returned {1}", $bwsApiName, $response.returnStatus.code.ToString()));
			
	if ($response.returnStatus.code.Equals("SUCCESS"))
	{
		$returnValue = $response.encodedUsername;
	}
	else
	{
		Write-Host([string]::Format("Error Message: {0}", $response.returnStatus.message));
	}
	
	Write-Host([string]::Format("...exiting {0} with value {1}", $methodName, $response.returnStatus.code.ToString()));
	return $returnValue;
}
<#
#<summary> Displays user details for user
#</summary
#<param name = "individualUser"> User object passed in.</param>
#<returns></returns>
#>
function DisplayUserDetails($individualUser)
{
	$bwsApiName = "bwsService.getUsersDetail()";
	
	$userList = @();
	$userList += $individualUser;
	
	$request = New-Object GetUsersDetailRequest;
	$response = New-Object GetUsersDetailResponse;
	$request.metadata = $Metadata;
	
	<# To help improve API performance, load only the required details.	#>
	$request.loadAccounts = $true;
	$request.loadDevices = $true;
	$request.loadITPolicies = $false;
	$request.users = $userList;
	
	Write-Host("-------------------");
	$response = $bwsService.getUsersDetail($request);
	
	if ($response.returnStatus.code.Equals("SUCCESS"))
	{
		if ($response.individualResponses -ne $null -and $response.individualResponses.Length -eq 1)
		{
			$userDetail = New-Object UserDetail;
			$userDetail = $response.individualResponses[0].userDetail;
			Write-Host([string]::Format("Display Name: {0}", $userDetail.displayName));
				
			$account = New-Object Account;
			foreach ($account in $userDetail.accounts)
			{
				Write-Host([string]::Format("Email Address: {0}", $account.emailAddress));
			}
			
			if ($userDetail.devices.Length -gt 0)
			{
				
				
				$device = New-Object Device;
				foreach ($device in $userDetail.devices)
				{
					Write-Host([string]::Format("PIN: {0}", $device.pin));
					Write-Host([string]::Format("Model: {0}", $device.model));
				}
			}
		}
		elseif ($response.individualResponses -ne 1)
		{
			Write-Host([string]::Format("Not exactly one user detail result was found for {0}", $individualUser.uid));
		}
	}
	else
	{
		Write-Host([string]::Format("Error Message: {0}", $response.returnStatus.message));
	}
}

<#
# <summary>
# Retrieves the first few users and loops through the users list and calls DisplayUserDetails() for each given user.
# </summary>
# <returns></returns>
#>
function GetUsersAndDisplaySomeUserData()
{
	$bwsApiName = "bwsService.getUsers()";
	
	#Array of users.
	$userList = @();
	$userList = $null;
	$request = New-Object GetUsersRequest;
	$request.metadata = $Metadata;
	
	$response = New-Object GetUsersResponse;
	$response = $null;
	
	$sortBy = New-Object GetUsersSortBy;
	$sortBy.EMAIL_ADDRESS = $true;
	$sortBy.value = "EMAIL_ADDRESS";
	$request.sortBy = $sortBy
	
	<#
	# Set pageSize to limit the number of results to something reasonable for this demo.
	#>
	$request.pageSize = 5;
	
	$response = $bwsService.getUsers($request);
		
	if ($response.returnStatus.code.Equals("SUCCESS"))
	{
		#Check to make user the response is greater than zero.
		if ($response.users.Length -gt 0)
		{
			$user = New-Object User;
			#loop though all users and display the details for the user.
			foreach ($user in $response.users)
			{
				DisplayUserDetails($user);
			}
		}
		else
		{
			Write-Host("No users were found");
		}
	}
	else
	{
		Write-Host([string]::Format("Error Message: {0}", $response.returnStatus.message));
	}
}

<#
<summary>
The Main Function.
</summary>
#>
function Main
{
	<#
	# BWS Host certificate must be installed on the client machine before running this sample code, otherwise
	# a SSL/TLS secure channel error will be thrown. For more information, see the BlackBerry Web Services for
	# Enterprise Administration For Microsoft .NET Developers Getting Started Guide.
	# http://docs.blackberry.com/en/admin/deliverables/60165/index.jsp?name=For+Microsoft+.NET+developers+-+Getting+Started+Guide+-+BlackBerry+Web+Services10.2.2&language=English&userType=2&category=BlackBerry+Web+Services&subCategory=BlackBerry+Web+Services+for+BlackBerry+Enterprise+Service+10
	#>
	Write-Host("Entering Main()...");
	try
	{
		if (Setup)
		{
			GetUsersAndDisplaySomeUserData;
		}
	}
	catch [Exception]
	{
		Write-Host([string]::Format("Exception type: {0}, Message: {1}", $_.Exception.GetType().FullName, $_.Exception.Message));
	}
	Write-Host("...exiting Main()");
}

<#
# <summary>
# Calls Main function.
# </summary>
#>
Main;
