/* 
 * Copyright (c) 2012 Research In Motion Limited. 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 * http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
import com.rim.ws.enterprise.admin.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceException;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.HTTPException;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;

/*
 * SampleBwsClient.java
 * 
 * A program that demonstrates BlackBerry Web Services (BWS) for Enterprise Administration APIs.
 * 
 * This sample program demonstrates how to get system information to make an authenticated API call. If successful, the
 * program then optionally creates a user and optionally displays the user's details. If the authenticated API is not
 * successful, the program displays a message indicating that the failure has occurred.
 * 
 * 
 * This program was tested against the BlackBerry Device Service version 6.0.0.
 */ 
 
public class SampleBwsClient
{
	private static BWSService _bwsService;
	private static BWS _bws;
	private static BWSUtilService _bwsUtilService;
	private static BWSUtil _bwsUtil;

	// The request Metadata information. 
	// This is the version of the WSDL used to generate the proxy, not the version of the server.
	private final static String CLIENT_VERSION = "6.0.0";
	
	/* 
	 * To use a different locale, call getLocales() in the BWSUtilService web service
	 * to see which locales are supported. 
	 */
	private final static String LOCALE = "en_US";
	private final static String ORG_UID = "0";
	private final static RequestMetadata REQUEST_METADATA = new RequestMetadata();

	// Authentication type name.
	private final static String AUTHENTICATOR_NAME = "BlackBerry Administration Service";

	// Hostname to use when connecting to web service.
	private final static String BWS_HOST_NAME = "<BWSHostName>"; // e.g. BWS_HOST_NAME = "server01.yourcompany.net".	
	private final static String USERNAME = "<username>"; // e.g. USERNAME = "admin".	
	private final static String PASSWORD = "<password>"; // e.g. PASSWORD = "password".


	/*
	 * Note about exact String searching: To use an email address as the search criteria for an exact string match
	 * search, it must be enclosed in double-quotes e.g. \"user01@example.net\". Enclosing search criteria in
	 * double-quotes causes an exact string match search to be performed.
	 * 
	 * Failing to enclose the email search criteria in double-quotes e.g. user01@example.net (no double-quotes) will
	 * result in a substring match search being performed. A substring match search in this case would return multiple
	 * undesired search results because searching with user01@example.net (no double-quotes) would not only match on the
	 * value user01@example.net, but would also match on the value someuser01@example.net and
	 * someotheruser01@example.net due to the fact that the substring user01@example.net satisfies the search criteria
	 * in all of these cases.
	 * 
	 * String searches are not case-sensitive. Wildcards and prefix or suffix matching is supported.
	 */

	// Email address used to create a new user with the createUsers() API call.
	private final static String CREATE_NEW_USER_EMAIL = "\"user01@example.net\"";

	// Email address used to identify the user to find with the getUsersDetail() API call.
	private final static String DISPLAY_USER_DETAIL_EMAIL = "\"user01@example.net\"";

	/*******************************************************************************************************************
	 * 
	 * Initialize the BWS and BWSUtil services.
	 * 
	 * @return Returns true when the setup is successful, and false otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	private static boolean setup()
	{
		final String METHOD_NAME = "setup()";
		System.err.format("Entering %s%n", METHOD_NAME);
		boolean returnValue = false;
		REQUEST_METADATA.setClientVersion(CLIENT_VERSION);
		REQUEST_METADATA.setLocale(LOCALE);
		REQUEST_METADATA.setOrganizationUid(ORG_UID);

		URL bwsServiceUrl = null;
		URL bwsUtilServiceUrl = null;

		try
		{
			// These are the URLs that point to the web services used for all calls.
			bwsServiceUrl = new URL("https://" + BWS_HOST_NAME + "/enterprise/admin/ws");
			bwsUtilServiceUrl = new URL("https://" + BWS_HOST_NAME + "/enterprise/admin/util/ws");
		}
		catch (MalformedURLException e)
		{

			System.err.format("Cannot initialize wsdl urls%n");
			System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
			return returnValue;
		}

		// Initialize the BWS web service stubs that will be used for all calls.
		QName serviceBWS = new QName("http://ws.rim.com/enterprise/admin", "BWSService");
		QName portBWS = new QName("http://ws.rim.com/enterprise/admin", "BWS");
		_bwsService = new BWSService(null, serviceBWS);
		_bwsService.addPort(portBWS, "http://schemas.xmlsoap.org/soap/", bwsServiceUrl.toString());
		_bws = _bwsService.getPort(portBWS,BWS.class);
		
		QName serviceUtil = new QName("http://ws.rim.com/enterprise/admin", "BWSUtilService");
		QName portUtil = new QName("http://ws.rim.com/enterprise/admin", "BWSUtil");
		_bwsUtilService = new BWSUtilService(null, serviceUtil);
		_bwsUtilService.addPort(portUtil, "http://schemas.xmlsoap.org/soap/", bwsUtilServiceUrl.toString());
		_bwsUtil = _bwsUtilService.getPort(portUtil, BWSUtil.class);

		// Set the connection timeout to 60 seconds.
		HTTPClientPolicy httpClientPolicy = new HTTPClientPolicy();
		httpClientPolicy.setConnectionTimeout(60000);

		httpClientPolicy.setAllowChunking(false);
		httpClientPolicy.setReceiveTimeout(60000);

		Client client = ClientProxy.getClient(_bws);
		HTTPConduit http = (HTTPConduit) client.getConduit();
		http.setClient(httpClientPolicy);

		client = ClientProxy.getClient(_bwsUtil);
		http = (HTTPConduit) client.getConduit();
		http.setClient(httpClientPolicy);

		Authenticator authenticator = getAuthenticator(AUTHENTICATOR_NAME);
		if (authenticator != null)
		{
			String encodedUsername = getEncodedUserName(USERNAME, authenticator);
			if (encodedUsername != null && !encodedUsername.isEmpty())
			{
				/* 
				 * Set the HTTP basic authentication on the BWS service.
				 * BWSUtilService is a utility web service that does not require
				 * authentication. 
				 */
				BindingProvider bp = (BindingProvider) _bws;
				bp.getRequestContext().put(BindingProvider.USERNAME_PROPERTY, encodedUsername);
				bp.getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, PASSWORD);

				returnValue = true;
			}
			else
			{
				System.err.format("'encodedUsername' is null or empty%n");
			}
		}
		else
		{
			System.err.format("'authenticator' is null%n");
		}

		System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Get the authenticator object for the authenticator name.
	 * 
	 * @param authenticatorName
	 *            A string containing the name of the desired authenticator.
	 * @return Returns the requested authenticator if it is found, null otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static Authenticator getAuthenticator(String authenticatorName)
	{
		final String METHOD_NAME = "getAuthenticator()";
		final String BWS_API_NAME = "_bwsUtil.getAuthenticators()";
		System.err.format("Entering %s%n", METHOD_NAME);
		Authenticator returnValue = null;

		GetAuthenticatorsRequest request = new GetAuthenticatorsRequest();
		request.setMetadata(REQUEST_METADATA);

		System.err.format("Calling %s...%n", BWS_API_NAME);
		GetAuthenticatorsResponse response = _bwsUtil.getAuthenticators(request);
		System.err.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus().getCode());

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			if (response.getAuthenticators() != null && !response.getAuthenticators().isEmpty())
			{
				for (Authenticator authenticator : response.getAuthenticators())
				{
					if (authenticator.getName().equalsIgnoreCase(authenticatorName))
					{
						returnValue = authenticator;
						break;
					}
				}

				if (returnValue == null)
				{
					System.err.format("Could not find \"%s\" in GetAuthenticatorsResponse%n", authenticatorName);
				}
			}
			else
			{
				System.err.format("No authenticators in GetAuthenticatorsResponse%n");
			}
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
		}

		System.err.format("Exiting %s with %s%n", METHOD_NAME, returnValue == null ? "\"null\""
				: "Authenticator object (Name \"" + returnValue.getName() + "\")");
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Get the encoded username required to authenticate user to BWS.
	 * 
	 * @param username
	 *            A string containing the username to encode.
	 * @param authenticator
	 *            The authenticator.
	 * @return Returns a string containing the encoded username if successful, and a null message string otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static String getEncodedUserName(String username, Authenticator authenticator)
	{
		final String METHOD_NAME = "getEncodedUserName()";
		final String BWS_API_NAME = "_bwsUtil.getEncodedUsername()";
		System.err.format("Entering %s%n", METHOD_NAME);
		String returnValue = null;

		GetEncodedUsernameRequest request = new GetEncodedUsernameRequest();
		request.setMetadata(REQUEST_METADATA);
		request.setUsername(username);
		request.setOrgUid(REQUEST_METADATA.getOrganizationUid());
		request.setAuthenticator(authenticator);

		CredentialType credentialType = new CredentialType();
		credentialType.setPASSWORD(true);
		credentialType.setValue("PASSWORD");
		request.setCredentialType(credentialType);

		System.err.format("Calling %s...%n", BWS_API_NAME);
		GetEncodedUsernameResponse response = _bwsUtil.getEncodedUsername(request);
		System.err.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus().getCode());

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			returnValue = response.getEncodedUsername();
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
		}

		System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue == null ? "null" : returnValue);
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Retrieves a single user using an email address. If more or less than one result is found, that is treated as an
	 * error.
	 * 
	 * @return Returns a User object if user is found, and null otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static User getUser()
	{
		final String METHOD_NAME = "getUser()";
		final String BWS_API_NAME = "_bws.getUsers()";
		System.err.format("Entering %s%n", METHOD_NAME);
		User returnValue = null;

		GetUsersRequest request = new GetUsersRequest();
		request.setMetadata(REQUEST_METADATA);

		GetUsersSearchCriteria searchCriteria = new GetUsersSearchCriteria();

		// Note: Email searches are not case-sensitive. Wildcards and prefix or suffix matching are supported.
		
		/* 
		 * Check if the value of the variable "DISPLAY_USER_DETAIL_EMAIL" is enclosed in double-quotes, and if it's not,
		 * then display a message. If the variable "DISPLAY_USER_DETAIL_EMAIL" is not enclosed in double-quotes, then a
		 * substring match search will be performed.
		 */
		if (!DISPLAY_USER_DETAIL_EMAIL.startsWith("\"") || !DISPLAY_USER_DETAIL_EMAIL.endsWith("\""))
		{
			System.err.format(	"Warning: Email Address \"%s\" is not enclosed in double-quotes%n",
								DISPLAY_USER_DETAIL_EMAIL);
		}
		searchCriteria.setEmailAddress(DISPLAY_USER_DETAIL_EMAIL);
		request.setSearchCriteria(searchCriteria);

		/* 
		 * The pageSize value of 2 is used to help determine if exactly 1 unique user was found. Using a pageSize value
		 * of 2 avoids the overhead of retrieving more than 2 search results.
		 */
		request.setPageSize(2);

		GetUsersSortBy sortBy = new GetUsersSortBy();
		sortBy.setEMAILADDRESS(true);
		sortBy.setValue("EMAIL_ADDRESS");
		request.setSortBy(sortBy);

		System.err.format("Calling %s...%n", BWS_API_NAME);
		GetUsersResponse response = _bws.getUsers(request);
		System.err.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus().getCode());

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			if (response.getUsers() != null && response.getUsers().size() == 1)
			{
				// Returns the first user object in the users list.
				returnValue = response.getUsers().get(0);
			}
			else if (response.getUsers() != null && response.getUsers().size() > 1)
			{
				System.err.format("More than one user was found with email address \"%s\"%n", 
				                  DISPLAY_USER_DETAIL_EMAIL);
			}
			else
			{
				System.err.format("No user was found with email address \"%s\"%n", DISPLAY_USER_DETAIL_EMAIL);
			}
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
		}

		System.err.format("Exiting %s with %s%n", METHOD_NAME, returnValue == null ? "\"null\"" : "User object (UID \""
				+ returnValue.getUid() + "\")");
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Retrieve and display some user details.
	 * 
	 * @return Returns true if getUsersDetail is successful, and false otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static boolean displayUserDetails()
	{
		final String METHOD_NAME = "displayUserDetails()";
		final String BWS_API_NAME = "_bws.getUsersDetail()";
		System.err.format("Entering %s%n", METHOD_NAME);
		boolean returnValue = false;

		System.err.format("Displaying details for user with email address \"%s\"%n", DISPLAY_USER_DETAIL_EMAIL);

		// Getting the user object.
		User user = getUser();

		if (user == null)
		{
			System.err.format("'user' is null%n");
			System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
			return returnValue;
		}

		GetUsersDetailRequest request = new GetUsersDetailRequest();
		request.setMetadata(REQUEST_METADATA);

		/*
		 * To help improve API performance, load only the required details.
		 * By default all load flags are set to false.
		 */
		request.setLoadAccounts(true);
		request.setLoadDevices(true);
		request.setLoadITPolicies(true);
		request.getUsers().add(user);

		System.err.format("Calling %s...%n", BWS_API_NAME);
		GetUsersDetailResponse response = _bws.getUsersDetail(request);
		System.err.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus().getCode());

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			if (response.getIndividualResponses() != null && response.getIndividualResponses().size() == 1)
			{
				for (GetUsersDetailIndividualResponse individualResponse : response.getIndividualResponses())
				{
					UserDetail userDetail = individualResponse.getUserDetail();

					System.out.format("User details:%n");
					// The values of the fields, and whether they will be populated or not, depends on the device type.
					System.out.format("Display Name: %s%n", userDetail.getDisplayName());
					System.out.format("User UID: %s%n", individualResponse.getUserUid());
					// Displays time in UTC format.
					System.out.format("Last Login Time: %s%n", userDetail.getLastLoginTime());
					if (userDetail.getIndirectITPolicies() != null && !userDetail.getIndirectITPolicies().isEmpty())
					{
						System.out.format("Indirect IT policy names: ");
						StringBuilder policyString = new StringBuilder();
						for (IndirectITPolicy indirectITPolicy : userDetail.getIndirectITPolicies())
						{
							if (policyString.length() > 0)
							{
								policyString.append(", ");
							}
							policyString.append(indirectITPolicy.getItPolicy().getPolicy().getName());
						}
						System.out.format("%s%n", policyString);
					}

					if (userDetail.getDirectITPolicy() != null && userDetail.getDirectITPolicy().getPolicy() != null)
					{
						System.out.format("Direct IT policy name: %s%n", userDetail.getDirectITPolicy().getPolicy()
																					.getName());
					}

					/*
					 * The BWS object model supports multiple accounts and devices. However, BES 5.0.3 will only return
					 * at most one object in the userDetail.getDevices() list, and at most one object in the
					 * userDetail.getAccounts() list.
					 */
					if (userDetail.getDevices() != null && !userDetail.getDevices().isEmpty())
					{
						System.out.format("User's device details:%n");

						int deviceIndex = 1;
						for (Device device : userDetail.getDevices())
						{
							System.out.format("Device %d data%n", (deviceIndex++));
							System.out.format("---------------%n");
							System.out.format("PIN: %s%n", device.getPin());
							System.out.format("Model: %s%n", device.getModel());
							System.out.format("Phone Number: %s%n", device.getPhoneNumber());
							System.out.format("Active Carrier: %s%n", device.getActiveCarrier());
							System.out.format("Network: %s%n", device.getNetwork());
							System.out.format("Serial Number: %s%n", device.getSerialNumber());
							System.out.format("State: %s%n", device.getState().getValue());
							System.out.format("IT Policy Name: %s%n", device.getItPolicyName());
							System.out.format("Platform Version: %s%n", device.getPlatformVersion());
							System.out.format("Total Messages Expired: %s%n", device.getTotalMessagesExpired());
							System.out.format("Total Messages Filtered: %s%n", device.getTotalMessagesFiltered());
							System.out.format("Total Messages Forwarded: %s%n", device.getTotalMessagesForwarded());
							System.out.format("Total Messages Pending: %s%n", device.getTotalMessagesPending());
							System.out.format("Total Messages Sent: %s%n", device.getTotalMessagesSent());
							System.out.format("---------------%n");
						}
					}

					if (userDetail.getAccounts() != null && !userDetail.getAccounts().isEmpty())
					{
						System.out.format("User's account details:%n");

						int accountIndex = 1;
						for (Account account : userDetail.getAccounts())
						{
							System.out.format("Account %d data%n", (accountIndex++));
							System.out.format("---------------%n");
							System.out.format("Email Address: %s%n", account.getEmailAddress());
							System.out.format("---------------%n");
						}
					}
				}

				returnValue = true;
			}
			else if (response.getIndividualResponses() != null && response.getIndividualResponses().size() > 1)
			{
				System.err.format("More than one user was found with userUid \"%s\"%n", user.getUid());
			}
			else
			{
				System.err.format("No user was found with userUid \"%s\"%n", user.getUid());
			}
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
			if (response.getIndividualResponses() != null)
			{
				for (GetUsersDetailIndividualResponse individualResponse : response.getIndividualResponses())
				{
					System.err.format("User UID: \"%s\"%n", individualResponse.getUserUid());
					System.err.format(	"Individual Response - Code: \"%s\", Message: \"%s\"%n",
										individualResponse.getReturnStatus().getCode(),
										individualResponse.getReturnStatus().getMessage());
				}
			}
		}

		System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Creates a user using an email address.
	 * 
	 * @return Returns true if createUsers is successful, and false otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static boolean createUser()
	{
		final String METHOD_NAME = "createUser()";
		final String BWS_API_NAME = "_bws.createUsers()";
		System.err.format("Entering %s%n", METHOD_NAME);
		boolean returnValue = false;

		// Create the request object.
		CreateUsersRequest createUsersRequest = new CreateUsersRequest();
		createUsersRequest.setMetadata(REQUEST_METADATA);

		NewUser newUser = new NewUser();
		
		// To create an administrator user, create and set the "UserAttributes".
		AccountAttributes accountAttributes = new AccountAttributes();

		/*
		 * Check if value of the variable "CREATE_NEW_USER_EMAIL" is enclosed in double-quotes, otherwise the string
		 * would infer a substring match search.
		 */
		if (!CREATE_NEW_USER_EMAIL.startsWith("\"") || !CREATE_NEW_USER_EMAIL.endsWith("\""))
		{
			System.err.format("Warning: Email Address \"%s\" is not enclosed in double-quotes%n", 
			                  CREATE_NEW_USER_EMAIL);
		}
		// Value of the variable "CREATE_NEW_USER_EMAIL" is used to create a BlackBerry-enabled user.
		System.err.format("Creating a user with email address \"%s\"%n", CREATE_NEW_USER_EMAIL);
		accountAttributes.setEmailAddress(CREATE_NEW_USER_EMAIL);

		newUser.setAccountAttributes(accountAttributes);
		// Randomly select a BlackBerry Enterprise Server on which to create the user.
		newUser.setServer(null);

		createUsersRequest.getNewUsers().add(newUser);

		System.err.format("Calling %s...%n", BWS_API_NAME);
		CreateUsersResponse response = _bws.createUsers(createUsersRequest);
		System.err.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus().getCode());

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			if (response.getIndividualResponses() != null)
			{
				for (IndividualResponse individualResponse : response.getIndividualResponses())
				{
					System.out.format(	"User created with UID \"%s\" using Email Address \"%s\"%n",
										individualResponse.getUid(), CREATE_NEW_USER_EMAIL);
				}

				returnValue = true;
			}
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
			if (response.getIndividualResponses() != null)
			{
				for (IndividualResponse individualResponse : response.getIndividualResponses())
				{
					System.err.format(	"Individual Response - Code: \"%s\", Message: \"%s\"%n",
										individualResponse.getReturnStatus().getCode(),
										individualResponse.getReturnStatus().getMessage());
				}
			}
		}

		System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * Call _bwsService.getSystemInfo() and display the returned properties.
	 * 
	 * @return Returns true if getSystemInfo is successful, and false otherwise.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static boolean getSystemInfo()
	{
		final String METHOD_NAME = "getSystemInfo()";
		final String BWS_API_NAME = "_bws.getSystemInfo()";
		System.err.format("Entering %s%n", METHOD_NAME);
		boolean returnValue = false;

		GetSystemInfoRequest request = new GetSystemInfoRequest();

		/*
		 * Setting the value of loadAuthenticatedUserProperties to true will cause the API to return additional
		 * properties about the current user, like the Authenticated User Uid property. The Authenticated User Uid
		 * property is often used to make self-service calls to APIs like getUsersDetail(), setUsersAutoSignature() and
		 * others.
		 */
		request.setLoadAuthenticatedUserProperties(true);
		request.setMetadata(REQUEST_METADATA);

		GetSystemInfoResponse response = null;

		/* 
		 * The try catch block here is used to illustrate how to handle a specific type of exception.
		 * For example, in this case we check to see if the error was caused by invalid credentials.
		 */
		try
		{
			System.err.format(String.format("Calling %s...%n", BWS_API_NAME));
			response = _bws.getSystemInfo(request);
			System.err.format(String.format("...%s returned \"%s\"%n", BWS_API_NAME, response.getReturnStatus()
																								.getCode()));
		}
		catch (WebServiceException e)
		{
			if (e.getCause() instanceof HTTPException)
			{
				HTTPException httpException = (HTTPException) e.getCause();
				// Handle authentication failure.
				if (httpException != null && httpException.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED)
				{
					System.err.format("Failed to authenticate with the BWS web service%n");
					System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
					return returnValue;
				}
			}
			else
			{
				// Re-throw other exceptions.
				throw e;
			}
		}

		if (response.getMetadata() != null)
		{			
			/* 
             * Converting response.getMetadata().getExecutionTime() (which is in nano-seconds) into seconds by 
             * multiplying it by 10^-9.
             */
			System.err.format(	"%s Execution Time: %.4f seconds%n", BWS_API_NAME,
								(response.getMetadata().getExecutionTime() * Math.pow(10, -9)));
			System.err.format("%s Request UID: %s%n", BWS_API_NAME, response.getMetadata().getRequestUid());
		}

		if (response.getReturnStatus().getCode().equals("SUCCESS"))
		{
			if (response.getProperties() != null && !response.getProperties().isEmpty())
			{
				System.err.format("%s returned the following properties:%n", BWS_API_NAME);
				for (Property property : response.getProperties())
				{
					System.out.format("%s: %s%n", property.getName(), property.getValue());
				}

				returnValue = true;
			}
			else
			{
				System.err.format("No properties in response%n");
			}
		}
		else
		{
			System.err.format(	"Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(),
								response.getReturnStatus().getMessage());
		}

		System.err.format("Exiting %s with value \"%s\"%n", METHOD_NAME, returnValue);
		return returnValue;
	}

	/*******************************************************************************************************************
	 * 
	 * The main method.
	 * 
	 * @param args
	 *            not used.
	 * @throws IOException
	 *             if it fails to create log files.
	 * 
	 ******************************************************************************************************************* 
	 */
	public static void main(String[] args) throws IOException
	{
		// Return codes
		final int SUCCESS = 0;
		final int FAILURE = 1;
		int returnCode = SUCCESS;

		/* 
		 * Flags that are used to determine whether or not
		 * createUser() and displayUserDetails() gets called.
		 */
		boolean createNewUser = false;
		boolean displayUserDetails = true;

		// Write standard output / error streams to text files.
		System.setErr(System.out);

		/* 
         * BWS Host certificate must be installed on the client machine before running this sample code, otherwise
         * a SSL/TLS secure channel error will be thrown. For more information, see the BlackBerry Web Services for
         * Enterprise Administration For Java Developers Getting Started Guide.
         */
		try
		{
			System.err.format("Initializing web services...%n");
			if (setup())
			{
				/* 
				 * Demonstrate call to _bws.getSystemInfo() API.
				 * This is also the first authenticated call in the client application.
				 */
				System.err.format("Getting system information...%n");
				if (getSystemInfo())
				{
					if (createNewUser)
					{
						// Demonstrate call to _bws.createUsers() API.
						System.err.format("Creating a user...%n");
						if (!createUser())
						{
							System.err.format("Error: createUser() failed%n");
							returnCode = FAILURE;
						}
					}

					if (displayUserDetails)
					{
						// Demonstrate call to _bws.getUsers() and _bws.getUsersDetail() APIs.
						System.err.format("Displaying a user's details...%n");
						if (!displayUserDetails())
						{
							System.err.format("Error: displayUserDetails() failed%n");
							returnCode = FAILURE;
						}
					}
				}
				else
				{
					System.err.format("Error: getSystemInfo() failed%n");
					returnCode = FAILURE;
				}
			}
			else
			{
				System.err.format("Error: setup() failed%n");
				returnCode = FAILURE;
			}
		}
		catch (Exception e)
		{
			System.err.format(String.format("Exception: \"%s\"%n", e.getMessage()));
			returnCode = FAILURE;
		}

		System.err.format("Press Enter to exit%n");
		System.in.read();

		System.exit(returnCode);
	}
}