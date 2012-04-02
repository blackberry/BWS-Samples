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
using System;
using System.Net;
using System.IO;
using System.Collections.Generic;
using System.Text;

/*
 * SampleBwsClient.cs
 * 
 * A program that demonstrates BlackBerry Web Services (BWS) for Enterprise Administration APIs. 
 * 
 * This sample program demonstrates how to get system information to make an authenticated API call. If successful, the
 * program then optionally creates a user and optionally displays the user's details. If the authenticated API is not
 * successful, the program displays a message indicating that the failure has occurred.
 * 
 * This program was tested against the BlackBerry Device Service version 6.0.0.
 */


namespace Rim.Bws.Samples
{
    class SampleBwsClient
    {
        private static BWSService bwsService;
        private static BWSUtilService bwsUtilService;

        // The request Metadata information.
        // This is the version of the WSDL used to generate the proxy, not the version of the server.	
        private const string ClientVersion = "6.0.0";

        /*
         * To use a different locale, call getLocales() in the BWSUtilService web service
         * to see which locales are supported. 
         */
        private const string Locale = "en_US";
        private const string OrgUid = "0";
        private static readonly RequestMetadata Metadata = new RequestMetadata();

        // Authentication type name.
        private const string AuthenticatorName = "BlackBerry Administration Service";

        // Hostname to use when connecting to web service.        
        private const string BWSHostName = "<BWSHostName>"; // e.g. BWSHostName = "server01.yourcompany.net".        
        private const string Username = "<username>"; // e.g. Username = "admin".        
        private const string Password = "<password>"; // e.g. Password = "password".

        /*
         * Note about exact String Searching: To use an email address as the search criteria for an exact string match 
         * search, it must be enclosed in double-quotes e.g. \"user01@example.net\". Enclosing search criteria in 
         * double-quotes causes an exact string match search to be performed.
         * 
         * Failing to enclose the email search criteria in double-quotes e.g. user01@example.net (no double-quotes)
         * will result in a substring match search being performed. A substring match search in this case would return 
         * multiple undesired search results because searching with user01@example.net (no double-quotes) would 
         * not only match on the value user01@example.net, but would also match on the value 
         * someuser01@example.net and someotheruser01@example.net due to the fact that the substring 
         * user01@example.net satisfies the search criteria in all of these cases.
         * 
         * String searches are not case-sensitive. Wildcards and prefix or suffix matching is supported.
         */

        // Email address used to create a new user with the createUsers() API call.
        private const string CreateNewUserEmail = "\"user01@example.net\"";

        // Email address used to identify the user to find with the getUsersDetail() API call.
        private const string DisplayUserDetailsEmail = "\"user01@example.net\"";

        /// <summary>
        /// Initialize the BWS and BWSUtil services.
        /// </summary>
        /// <returns>Returns true when the setup is successful, and false otherwise.</returns>
        private static bool Setup()
        {
            const string methodName = "Setup()";
            Console.Error.WriteLine("Entering {0}", methodName);
            bool returnValue = false;

            Metadata.clientVersion = ClientVersion;
            Metadata.locale = Locale;
            Metadata.organizationUid = OrgUid;

            bwsService = new BWSService();
            bwsUtilService = new BWSUtilService();
            // URLs for the web services. This URL points to the main web service page.
            bwsService.Url = "https://" + BWSHostName + "/enterprise/admin/ws";
            bwsUtilService.Url = "https://" + BWSHostName + "/enterprise/admin/util/ws";

            // Set the connection timeout to 60 seconds.
            bwsService.Timeout = 60000;
            bwsUtilService.Timeout = 60000;

            Authenticator authenticator = GetAuthenticator(AuthenticatorName);
            if (authenticator != null)
            {
                string encodedUsername = GetEncodedUserName(Username, authenticator);
                if (!string.IsNullOrEmpty(encodedUsername))
                {
                    /* 
                     * Set the HTTP basic authentication on the BWS service.
                     * BWSUtilService is a utility web service that does not require
                     * authentication. 
                     */
                    bwsService.Credentials = new NetworkCredential(encodedUsername, Password);

                    /* 
                     * Send an HTTP Authorization header with requests after authentication
                     * has taken place. 
                     */
                    bwsService.PreAuthenticate = true;
                    returnValue = true;
                }
                else
                {
                    Console.Error.WriteLine("'encodedUsername' is null or empty");
                }
            }
            else
            {
                Console.Error.WriteLine("'authenticator' is null");
            }

            Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
            return returnValue;
        }

        /// <summary>
        /// Get the authenticator object for the authenticator name.
        /// </summary>
        /// <param name="authenticatorName">A string containing the name of the desired authenticator.</param>
        /// <returns>Returns the requested authenticator if it is found, and null otherwise.</returns>
        public static Authenticator GetAuthenticator(string authenticatorName)
        {
            const string methodName = "GetAuthenticator()";
            const string bwsApiName = "bwsUtilService.getAuthenticators()";
            Console.Error.WriteLine("Entering {0}", methodName);
            Authenticator returnValue = null;

            GetAuthenticatorsRequest request = new GetAuthenticatorsRequest();
            request.metadata = Metadata;

            Console.Error.WriteLine("Calling {0}...", bwsApiName);
            GetAuthenticatorsResponse response = bwsUtilService.getAuthenticators(request);
            Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.authenticators != null && response.authenticators.Length > 0)
                {
                    foreach (Authenticator authenticator in response.authenticators)
                    {
                        if (authenticator.name.Equals(authenticatorName, StringComparison.CurrentCultureIgnoreCase))
                        {
                            returnValue = authenticator;
                            break;
                        }
                    }

                    if (returnValue == null)
                    {
                        Console.Error.WriteLine("Could not find \"{0}\" in GetAuthenticatorsResponse",
                            authenticatorName);
                    }
                }
                else
                {
                    Console.Error.WriteLine("No authenticators in GetAuthenticatorsResponse");
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
            }

            Console.Error.WriteLine("Exiting {0} with {1}", methodName, returnValue == null ? "\"null\"" :
                "Authenticator object (Name \"" + returnValue.name + "\")");
            return returnValue;
        }

        /// <summary>
        /// Get the encoded username required to authenticate user to BWS.
        /// </summary>
        /// <param name="username">A string containing the username to encode.</param>
        /// <param name="authenticator">The authenticator.</param>
        /// <returns>Returns a string containing the encoded username if successful, and a null message string 
        /// otherwise.</returns>
        public static string GetEncodedUserName(string username, Authenticator authenticator)
        {
            const string methodName = "GetEncodedUserName()";
            const string bwsApiName = "bwsUtilService.getEncodedUsername()";
            Console.Error.WriteLine("Entering {0}", methodName);
            string returnValue = null;

            GetEncodedUsernameRequest request = new GetEncodedUsernameRequest();
            request.metadata = Metadata;
            request.username = username;
            request.orgUid = Metadata.organizationUid;
            request.authenticator = authenticator;

            CredentialType credentialType = new CredentialType();
            credentialType.PASSWORD = true;
            credentialType.value = "PASSWORD";
            request.credentialType = credentialType;

            Console.Error.WriteLine("Calling {0}...", bwsApiName);
            GetEncodedUsernameResponse response = bwsUtilService.getEncodedUsername(request);
            Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                returnValue = response.encodedUsername;
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
            }

            Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue == null ? "null" :
                returnValue);
            return returnValue;
        }

        /// <summary>
        /// Retrieves a single user using an email address. If more or less than one result is found, that is treated 
        /// as an error.
        /// </summary>
        /// <returns>Returns a User object if user is found, and null otherwise.</returns>
        public static User GetUser()
        {
            const string methodName = "GetUser()";
            const string bwsApiName = "bwsService.getUsers()";
            Console.Error.WriteLine("Entering {0}", methodName);
            User returnValue = null;

            GetUsersRequest request = new GetUsersRequest();
            request.metadata = Metadata;

            GetUsersSearchCriteria searchCriteria = new GetUsersSearchCriteria();


            // Note: Email searches are not case-sensitive. Wildcards and prefix or suffix matching are supported.

            /*
             * Check if the value of the variable "DisplayUserDetailsEmail" is enclosed in double-quotes, and if it's
             * not, then display a message. If the variable "DisplayUserDetailsEmail" is not enclosed in double-quotes,
             * then a substring match search will be performed.
             */
            if (!DisplayUserDetailsEmail.StartsWith("\"") || !DisplayUserDetailsEmail.EndsWith("\""))
            {
                Console.Error.WriteLine("Warning: Email Address \"{0}\" is not enclosed in double-quotes",
                    DisplayUserDetailsEmail);
            }
            searchCriteria.emailAddress = DisplayUserDetailsEmail;
            request.searchCriteria = searchCriteria;

            /* 
		     * The pageSize value of 2 is used to help determine if exactly 1 unique user was found. Using a pageSize value
		     * of 2 avoids the overhead of retrieving more than 2 search results.
		     */
            request.pageSize = 2;

            GetUsersSortBy sortBy = new GetUsersSortBy();
            sortBy.EMAIL_ADDRESS = true;
            sortBy.value = "EMAIL_ADDRESS";
            request.sortBy = sortBy;

            Console.Error.WriteLine("Calling {0}...", bwsApiName);
            GetUsersResponse response = bwsService.getUsers(request);
            Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.users != null && response.users.Length == 1)
                {
                    // Returns the first user object in the users array.
                    returnValue = response.users [0];
                }
                else if (response.users != null && response.users.Length > 1)
                {
                    Console.Error.WriteLine("More than one user was found with email address \"{0}\"",
                        DisplayUserDetailsEmail);
                }
                else
                {
                    Console.Error.WriteLine("No user was found with email address \"{0}\"", DisplayUserDetailsEmail);
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
            }

            Console.Error.WriteLine("Exiting {0} with {1}", methodName, returnValue == null ? "\"null\"" :
                "User object (UID \"" + returnValue.uid + "\")");
            return returnValue;
        }

        /// <summary>
        /// Retrieve and display some user details.
        /// <returns>Returns true if getUsersDetail is successful, and false otherwise.</returns>
        /// </summary>
        public static bool DisplayUserDetails()
        {
            const string methodName = "DisplayUserDetails()";
            const string bwsApiName = "bwsService.getUsersDetail()";
            Console.Error.WriteLine("Entering {0}", methodName);
            bool returnValue = false;

            // Getting the user object.
            User user = GetUser();
            Console.Error.WriteLine("Displaying details for user with email address \"{0}\"",
                DisplayUserDetailsEmail);

            if (user == null)
            {
                Console.Error.WriteLine("'user' is null");
                Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
                return returnValue;
            }

            List<User> users = new List<User>();
            users.Add(user);

            GetUsersDetailRequest request = new GetUsersDetailRequest();
            request.metadata = Metadata;

            /*
		     * To help improve API performance, load only the required details.
		     * By default all load flags are set to false.
		     */
            request.loadAccounts = true;
            request.loadDevices = true;
            request.loadITPolicies = true;
            request.users = users.ToArray();

            Console.Error.WriteLine("Calling {0}...", bwsApiName);
            GetUsersDetailResponse response = bwsService.getUsersDetail(request);
            Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.individualResponses != null && response.individualResponses.Length == 1)
                {
                    foreach (GetUsersDetailIndividualResponse individualResponse in response.individualResponses)
                    {
                        UserDetail userDetail = individualResponse.userDetail;

                        Console.WriteLine("User details:");

                        Console.WriteLine("Display Name: {0}", userDetail.displayName);
                        Console.WriteLine("User UID: {0}", individualResponse.userUid);

                        // Displays time in UTC format.
                        Console.WriteLine("Last Login Time: {0}", userDetail.lastLoginTime);
                        if (userDetail.indirectITPolicies != null && userDetail.indirectITPolicies.Length > 0)
                        {
                            Console.Write("Indirect IT policy names: ");
                            StringBuilder policyString = new StringBuilder();
                            foreach (IndirectITPolicy indirectITPolicy in userDetail.indirectITPolicies)
                            {
                                if (policyString.Length > 0)
                                {
                                    policyString.Append(", ");
                                }
                                policyString.Append(indirectITPolicy.itPolicy.policy.name);
                            }
                            Console.WriteLine(policyString);
                        }

                        if (userDetail.directITPolicy != null && userDetail.directITPolicy.policy != null)
                        {
                            Console.WriteLine("Direct IT policy name: {0}", userDetail.directITPolicy.policy.name);
                        }

                        /*
                         * The BWS object model supports multiple accounts and devices. However, BES 5.0.3 will only   
                         * return at most one object in the userDetail.devices array, and at most one object in the 
                         * userDetail.accounts array.
                         */
                        if (userDetail.devices != null && userDetail.devices.Length > 0)
                        {
                            Console.WriteLine("User's device details:");

                            int deviceIndex = 1;
                            foreach (Device device in userDetail.devices)
                            {
                                Console.WriteLine("Device {0} data", (deviceIndex++));
                                Console.WriteLine("---------------");
                                Console.WriteLine("PIN: {0}", device.pin);
                                Console.WriteLine("Model: {0}", device.model);
                                Console.WriteLine("Phone Number: {0}", device.phoneNumber);
                                Console.WriteLine("Active Carrier: {0}", device.activeCarrier);
                                Console.WriteLine("Network: {0}", device.network);
                                Console.WriteLine("Serial Number: {0}", device.serialNumber);
                                Console.WriteLine("State: {0}", device.state.value);
                                Console.WriteLine("IT Policy Name: {0}", device.itPolicyName);
                                Console.WriteLine("Platform Version: {0}", device.platformVersion);
                                Console.WriteLine("Total Messages Expired: {0}", device.totalMessagesExpired);
                                Console.WriteLine("Total Messages Filtered: {0}", device.totalMessagesFiltered);
                                Console.WriteLine("Total Messages Forwarded: {0}", device.totalMessagesForwarded);
                                Console.WriteLine("Total Messages Pending: {0}", device.totalMessagesPending);
                                Console.WriteLine("Total Messages Sent: {0}", device.totalMessagesSent);
                                Console.WriteLine("---------------");
                            }
                        }

                        if (userDetail.accounts != null && userDetail.accounts.Length > 0)
                        {
                            Console.WriteLine("User's account details:");

                            int accountIndex = 1;
                            foreach (Account account in userDetail.accounts)
                            {
                                Console.WriteLine("Account {0} data", (accountIndex++));
                                Console.WriteLine("---------------");
                                Console.WriteLine("Email Address: {0}", account.emailAddress);
                                Console.WriteLine("---------------");
                            }
                        }
                    }

                    returnValue = true;
                }
                else if (response.individualResponses != null && response.individualResponses.Length > 1)
                {
                    Console.Error.WriteLine("More than one user was found with userUid \"{0}\"",
                        user.uid);
                }
                else
                {
                    Console.Error.WriteLine("No user was found with userUid \"{0}\"", user.uid);
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
                if (response.individualResponses != null)
                {
                    foreach (GetUsersDetailIndividualResponse individualResponse in response.individualResponses)
                    {
                        Console.Error.WriteLine("User UID: \"{0}\"", individualResponse.userUid);
                        Console.Error.WriteLine("Individual Response - Code: \"{0}\", Message: \"{1}\"",
                            individualResponse.returnStatus.code, individualResponse.returnStatus.message);
                    }
                }
            }

            Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
            return returnValue;
        }

        /// <summary>
        /// Creates a user using an email address.
        /// <returns>Returns true if createUsers is successful, and false otherwise.</returns>
        /// </summary>
        public static bool CreateUser()
        {
            const string methodName = "CreateUser()";
            const string bwsApiName = "bwsService.createUsers()";
            Console.Error.WriteLine("Entering {0}", methodName);
            bool returnValue = false;

            // Create the request object.
            CreateUsersRequest createUsersRequest = new CreateUsersRequest();
            createUsersRequest.metadata = Metadata;

            NewUser newUser = new NewUser();
            
            // To create an administrator user, create and set the "UserAttributes".
            AccountAttributes accountAttributes = new AccountAttributes();

            /* 
             * Check if value of the variable "CreateNewUserEmail" is enclosed in double-quotes,
             * otherwise the string would infer a substring match search.
             */
            if (!CreateNewUserEmail.StartsWith("\"") || !CreateNewUserEmail.EndsWith("\""))
            {
                Console.Error.WriteLine("Warning: Email Address \"{0}\" is not enclosed in double-quotes",
                    CreateNewUserEmail);
            }
            // Value of the variable "CreateNewUserEmail" is used to create a BlackBerry-enabled user.
            Console.Error.WriteLine("Creating a user with email address \"{0}\"", CreateNewUserEmail);
            accountAttributes.emailAddress = CreateNewUserEmail;

            newUser.accountAttributes = accountAttributes;
            // Randomly select a BlackBerry Enterprise Server on which to create the user.
            newUser.server = null;

            List<NewUser> newUsers = new List<NewUser>();
            newUsers.Add(newUser);
            createUsersRequest.newUsers = newUsers.ToArray();

            Console.Error.WriteLine("Calling {0}...", bwsApiName);
            CreateUsersResponse response = bwsService.createUsers(createUsersRequest);
            Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.individualResponses != null)
                {
                    foreach (IndividualResponse individualResponse in response.individualResponses)
                    {
                        Console.WriteLine("User created with UID \"{0}\" using Email Address \"{1}\"",
                            individualResponse.uid, CreateNewUserEmail);
                    }

                    returnValue = true;
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
                if (response.individualResponses != null)
                {
                    foreach (IndividualResponse individualResponse in response.individualResponses)
                    {
                        Console.Error.WriteLine("Individual Response - Code: \"{0}\", Message: \"{1}\"",
                            individualResponse.returnStatus.code, individualResponse.returnStatus.message);
                    }
                }
            }

            Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
            return returnValue;
        }

        /// <summary>
        /// Call bwsService.getSystemInfo() and display the returned properties.
        /// <returns>Returns true if getSystemInfo is successful, and false otherwise.</returns>
        /// </summary>
        public static bool GetSystemInfo()
        {
            const string methodName = "GetSystemInfo()";
            const string bwsApiName = "bwsService.getSystemInfo()";
            Console.Error.WriteLine("Entering {0}", methodName);
            bool returnValue = false;

            GetSystemInfoRequest request = new GetSystemInfoRequest();

            /* 
             * Setting the value of loadAuthenticatedUserProperties to true will cause the API to return additional 
             * properties about the current user, like the Authenticated User Uid property. The Authenticated User Uid 
             * property is often used to make self-service calls to APIs like getUsersDetail(), setUsersAutoSignature()
             * and others.
             */
            request.loadAuthenticatedUserProperties = true;
            request.metadata = Metadata;

            GetSystemInfoResponse response = null;

            /* 
             * The try catch block here is used to illustrate how to handle a specific type of exception.
             * For example, in this case we check to see if the error was caused by invalid credentials.
             */
            try
            {
                Console.Error.WriteLine("Calling {0}...", bwsApiName);
                response = bwsService.getSystemInfo(request);
                Console.Error.WriteLine("...{0} returned \"{1}\"", bwsApiName, response.returnStatus.code);
            }
            catch (WebException e)
            {
                HttpWebResponse webResponse = e.Response as HttpWebResponse;
                // Handle authentication failure.
                if (webResponse != null && webResponse.StatusCode == HttpStatusCode.Unauthorized)
                {
                    Console.Error.WriteLine("Failed to authenticate with the BWS web service");
                    Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
                    return returnValue;
                }
                else
                {
                    // Re-throw other exceptions.
                    throw e;
                }
            }

            if (response.metadata != null)
            {
                /* 
                 * Converting response.metadata.executionTime (which is in nano-seconds) into seconds by 
                 * multiplying it by 10^-9.
                 */
                Console.Error.WriteLine("{0} Execution Time: {1:0.0000} seconds", bwsApiName,
                    (response.metadata.executionTime * Math.Pow(10, -9)));
                Console.Error.WriteLine("{0} Request UID: {1}", bwsApiName, response.metadata.requestUid);
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.properties != null && response.properties.Length > 0)
                {
                    Console.Error.WriteLine("{0} returned the following properties:", bwsApiName);
                    foreach (Property property in response.properties)
                    {
                        Console.WriteLine("{0}: {1}", property.name, property.value);
                    }

                    returnValue = true;
                }
                else
                {
                    Console.Error.WriteLine("No properties in response");
                }
            }
            else
            {
                Console.Error.WriteLine("Error: Code: \"{0}\", Message: \"{1}\"", response.returnStatus.code,
                    response.returnStatus.message);
            }

            Console.Error.WriteLine("Exiting {0} with value \"{1}\"", methodName, returnValue);
            return returnValue;
        }

        /// <summary>
        /// The Main function.
        /// </summary>
        static int Main(string [] args)
        {
            // Return codes.
            const int success = 0;
            const int failure = 1;
            int returnCode = success;

            /* 
             * Flags that are used to determine whether or not 
             * CreateUser() and DisplayUserDetails() gets called.
             */
            bool createNewUser = true;
            bool displayUserDetails = true;

            /* 
             * BWS Host certificate must be installed on the client machine before running this sample code, otherwise
             * a SSL/TLS secure channel error will be thrown. For more information, see the BlackBerry Web Services for
             * Enterprise Administration For Microsoft .NET Developers Getting Started Guide.
             */
            try
            {
                Console.Error.WriteLine("Initializing web services...");
                if (Setup())
                {
                    /* 
                     * Demonstrate call to bwsService.getSystemInfo().
                     * This is also the first authenticated call in the client application.
                     */
                    Console.Error.WriteLine("Getting system information...");
                    if (GetSystemInfo())
                    {
                        if (createNewUser)
                        {
                            Console.Error.WriteLine("Creating a user...");

                            // Demonstrate call to bwsService.createUsers() API.
                            if (!CreateUser())
                            {
                                Console.Error.WriteLine("Error: CreateUser() failed");
                                returnCode = failure;
                            }
                        }

                        if (displayUserDetails)
                        {
                            Console.Error.WriteLine("Displaying a user's details...");

                            // Demonstrate call to bwsService.getUsers() and bwsService.getUsersDetail() APIs.
                            if (!DisplayUserDetails())
                            {
                                Console.Error.WriteLine("Error: DisplayUserDetails() failed");
                                returnCode = failure;
                            }
                        }
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: GetSystemInfo() failed");
                        returnCode = failure;
                    }
                }
                else
                {
                    Console.Error.WriteLine("Error: Setup() failed");
                    returnCode = failure;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Exception: \"{0}\"", e.Message);
                returnCode = failure;
            }

            Console.Error.WriteLine("Press Enter to exit");
            Console.ReadKey();

            return returnCode;
        }
    }
}