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
using System.Diagnostics;
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
        // Web service stubs.
        private static BWSService bwsService;
        private static BWSUtilService bwsUtilService;

        // Timer used by logging.
        private static Stopwatch startTime = new Stopwatch();
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
        private static string BWSHostName = null; // e.g. BWSHostName = "server01.yourcompany.net".        
        private static string Username = null; // e.g. Username = "admin".        
        private static string Password = null; // e.g. Password = "password".

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
        private static string CreateNewUserEmail = null;

        // Email address used to identify the user to find with the getUsersDetail() API call.
        private static string DisplayUserDetailsEmail = null;

        /// <summary>
        /// Initialize the BWS and BWSUtil services.
        /// </summary>
        /// <returns>Returns true when the setup is successful, and false otherwise.</returns>
        private static bool Setup()
        {
            const string methodName = "Setup()";
            logMessage("Entering {0}", methodName);
            bool returnValue = false;

            Metadata.clientVersion = ClientVersion;
            Metadata.locale = Locale;
            Metadata.organizationUid = OrgUid;

            logMessage("Initializing BWS web service stub");
            bwsService = new BWSService();
            logMessage("BWS web service stub initialized");
            logMessage("Initializing BWSUtil web service stub");
            bwsUtilService = new BWSUtilService();
            logMessage("BWSUtil web service stub initialized");
            // These are the URLs that point to the web services used for all calls.
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
                    logMessage("'encodedUsername' is null or empty");
                }
            }
            else
            {
                logMessage("'authenticator' is null");
            }

            logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
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
            logMessage("Entering {0}", methodName);
            Authenticator returnValue = null;

            GetAuthenticatorsRequest request = new GetAuthenticatorsRequest();
            request.metadata = Metadata;

            GetAuthenticatorsResponse response = null;

            try
            {
                logRequest(bwsApiName);
                response = bwsUtilService.getAuthenticators(request);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
            }

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
                        logMessage("Could not find \"{0}\" in GetAuthenticatorsResponse",
                            authenticatorName);
                    }
                }
                else
                {
                    logMessage("No authenticators in GetAuthenticatorsResponse");
                }
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
            }

            logMessage("Exiting {0} with {1}", methodName, returnValue == null ? "\"null\"" :
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
            logMessage("Entering {0}", methodName);
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

            GetEncodedUsernameResponse response = null;

            try
            {
                logRequest(bwsApiName);
                response = bwsUtilService.getEncodedUsername(request);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                returnValue = response.encodedUsername;
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
            }

            logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue == null ? "null" :
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
            logMessage("Entering {0}", methodName);
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
                logMessage("Warning: Email Address \"{0}\" is not enclosed in double-quotes",
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

            GetUsersResponse response = null;

            try
            {
                logRequest(bwsApiName);
                response = bwsService.getUsers(request);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.users != null && response.users.Length == 1)
                {
                    // Returns the first user object in the users array.
                    returnValue = response.users[0];
                }
                else if (response.users != null && response.users.Length > 1)
                {
                    logMessage("More than one user was found with email address \"{0}\"",
                        DisplayUserDetailsEmail);
                }
                else
                {
                    logMessage("No user was found with email address \"{0}\"", DisplayUserDetailsEmail);
                }
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
            }

            logMessage("Exiting {0} with {1}", methodName, returnValue == null ? "\"null\"" :
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
            logMessage("Entering {0}", methodName);
            bool returnValue = false;
            
            logMessage("Displaying details for user with email address \"{0}\"",
                DisplayUserDetailsEmail);
            
            // Getting the user object.
            User user = GetUser();
            
            if (user == null)
            {
                logMessage("'user' is null");
                logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
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

            GetUsersDetailResponse response = null;
            try
            {
                logRequest(bwsApiName);
                response = bwsService.getUsersDetail(request);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.individualResponses != null && response.individualResponses.Length == 1)
                {
                    foreach (GetUsersDetailIndividualResponse individualResponse in response.individualResponses)
                    {
                        UserDetail userDetail = individualResponse.userDetail;

                        displayResult("User details:");

                        displayResult("Display Name: {0}", userDetail.displayName);
                        displayResult("User UID: {0}", individualResponse.userUid);

                        // Displays time in UTC format.
                        displayResult("Last Login Time: {0}", userDetail.lastLoginTime);
                        if (userDetail.indirectITPolicies != null && userDetail.indirectITPolicies.Length > 0)
                        {
                            StringBuilder policyString = new StringBuilder();
                            foreach (IndirectITPolicy indirectITPolicy in userDetail.indirectITPolicies)
                            {
                                if (policyString.Length > 0)
                                {
                                    policyString.Append(", ");
                                }
                                policyString.Append(indirectITPolicy.itPolicy.policy.name);
                            }
                            displayResult("Indirect IT policy names: {0}", policyString.ToString());
                        }

                        if (userDetail.directITPolicy != null && userDetail.directITPolicy.policy != null)
                        {
                            displayResult("Direct IT policy name: {0}", userDetail.directITPolicy.policy.name);
                        }

                        /*
                         * The BWS object model supports multiple accounts and devices. However, BlackBerry Enterprise
                         * Server 5.0.3 or later will only return at most one object in the userDetail.devices array, and
                         * at most one object in the userDetail.accounts array.
                         */
                        if (userDetail.devices != null && userDetail.devices.Length > 0)
                        {
                            displayResult("User's device details:");

                            int deviceIndex = 1;
                            foreach (Device device in userDetail.devices)
                            {
                                displayResult("Device {0} data", (deviceIndex++));
                                displayResult("---------------");
                                displayResult("PIN: {0}", device.pin);
                                displayResult("Model: {0}", device.model);
                                displayResult("Phone Number: {0}", device.phoneNumber);
                                displayResult("Active Carrier: {0}", device.activeCarrier);
                                displayResult("Network: {0}", device.network);
                                displayResult("Serial Number: {0}", device.serialNumber);
                                displayResult("State: {0}", device.state.value);
                                displayResult("IT Policy Name: {0}", device.itPolicyName);
                                displayResult("Platform Version: {0}", device.platformVersion);
                                displayResult("Total Messages Expired: {0}", device.totalMessagesExpired);
                                displayResult("Total Messages Filtered: {0}", device.totalMessagesFiltered);
                                displayResult("Total Messages Forwarded: {0}", device.totalMessagesForwarded);
                                displayResult("Total Messages Pending: {0}", device.totalMessagesPending);
                                displayResult("Total Messages Sent: {0}", device.totalMessagesSent);
                                displayResult("---------------");
                            }
                        }

                        if (userDetail.accounts != null && userDetail.accounts.Length > 0)
                        {
                            displayResult("User's account details:");

                            int accountIndex = 1;
                            foreach (Account account in userDetail.accounts)
                            {
                                displayResult("Account {0} data", (accountIndex++));
                                displayResult("---------------");
                                displayResult("Email Address: {0}", account.emailAddress);
                                displayResult("---------------");
                            }
                        }
                    }

                    returnValue = true;
                }
                else if (response.individualResponses != null && response.individualResponses.Length > 1)
                {
                    logMessage("More than one user was found with userUid \"{0}\"",
                        user.uid);
                }
                else
                {
                    logMessage("No user was found with userUid \"{0}\"", user.uid);
                }
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
                if (response.individualResponses != null)
                {
                    foreach (GetUsersDetailIndividualResponse individualResponse in response.individualResponses)
                    {
                        logMessage("User UID: \"{0}\"", individualResponse.userUid);
                        logMessage("Individual Response - Code: \"{0}\", Message: \"{1}\"",
                            individualResponse.returnStatus.code, individualResponse.returnStatus.message);
                    }
                }
            }

            logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
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
            logMessage("Entering {0}", methodName);
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
                logMessage("Warning: Email Address \"{0}\" is not enclosed in double-quotes",
                    CreateNewUserEmail);
            }
            // Value of the variable "CreateNewUserEmail" is used to create a BlackBerry-enabled user.
            logMessage("Creating a user with email address \"{0}\"", CreateNewUserEmail);
            accountAttributes.emailAddress = CreateNewUserEmail;

            newUser.accountAttributes = accountAttributes;
            // Randomly select a BlackBerry Enterprise Server on which to create the user.
            newUser.server = null;

            List<NewUser> newUsers = new List<NewUser>();
            newUsers.Add(newUser);
            createUsersRequest.newUsers = newUsers.ToArray();

            CreateUsersResponse response = null;

            try
            {
                logRequest(bwsApiName);
                response = bwsService.createUsers(createUsersRequest);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.individualResponses != null)
                {
                    foreach (IndividualResponse individualResponse in response.individualResponses)
                    {
                        displayResult("User created with UID \"{0}\" using Email Address \"{1}\"",
                            individualResponse.uid, accountAttributes.emailAddress);
                    }

                    returnValue = true;
                }
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
                if (response.individualResponses != null)
                {
                    foreach (IndividualResponse individualResponse in response.individualResponses)
                    {
                        logMessage("Individual Response - Code: \"{0}\", Message: \"{1}\"",
                            individualResponse.returnStatus.code, individualResponse.returnStatus.message);
                    }
                }
            }

            logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
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
            logMessage("Entering {0}", methodName);
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
                logRequest(bwsApiName);
                response = bwsService.getSystemInfo(request);
                logResponse(bwsApiName, response.returnStatus.code, response.metadata);
            }
            catch (WebException e)
            {
                HttpWebResponse webResponse = e.Response as HttpWebResponse;
                // Handle authentication failure.
                if (webResponse != null && webResponse.StatusCode == HttpStatusCode.Unauthorized)
                {
                    logMessage("Failed to authenticate with the BWS web service");
                    logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
                    return returnValue;
                }
                // Log and re-throw exception.
                logMessage("Exiting {0} with exception \"{1}\"", methodName, e.Message);
                throw e;
                
            }

            if (response.returnStatus.code.Equals("SUCCESS"))
            {
                if (response.properties != null && response.properties.Length > 0)
                {
                    logMessage("{0} returned the following properties:", bwsApiName);
                    foreach (Property property in response.properties)
                    {
                        displayResult("{0}: {1}", property.name, property.value);
                    }

                    returnValue = true;
                }
                else
                {
                    logMessage("No properties in response");
                }
            }
            else
            {
                logMessage("Error Message: \"{0}\"", response.returnStatus.message);
            }

            logMessage("Exiting {0} with value \"{1}\"", methodName, returnValue);
            return returnValue;
        }

        /// <summary>
        /// Creates a string containing the elapsed time since the program started.
        /// The execution time will be reset to 00:00.000 if the execution time exceeds an hour. 
        /// <returns>Returns the elapsed time from start of program.</returns>
        /// </summary>
        public static String logTime()
        {
            String time = startTime.Elapsed.ToString();
            // trim decimals to 3 digits for seconds
            time = time.Substring(0, time.IndexOf('.') + 4);
            // get rid of HH:
            time = time.Substring(3);
            return time;
        }

        /// <summary>
        /// Prints a log message to stderr. 
        /// Appends the message to a string containing the elapsed time of the program.
        /// <param name="format">A string which formats how args will be displayed in the message.</param>
        /// <param name="args">Array of objects to be displayed in the message.</param>
        /// </summary>
        public static void logMessage(String format, params Object[] args)
        {   //Change output stream if desired
            TextWriter logStream = Console.Error;
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            logStream.WriteLine(logTime() + " " + format, args);
        }

        /// <summary>
        /// Prints results to stderr. 
        /// <param name="format">A string which formats how args will be displayed in the message.</param>
        /// <param name="args">Array of objects to be displayed in the message.</param>
        /// </summary>
        public static void displayResult(String format, params Object[] args)
        {   //Change output stream if desired
            TextWriter resultStream = Console.Error;
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            resultStream.WriteLine(format, args);
        }

        /// <summary>
        /// Logs the calling of an API. 
        /// <param name="bwsApiName">A string of the API called.</param>
        /// </summary>
        public static void logRequest(String bwsApiName)
        {
            logMessage("Calling {0}...", bwsApiName);
        }

        /// <summary>
        /// Logs various information about an API response. 
        /// <param name="bwsApiName">A string of the API called.</param>
        /// <param name="code">The return code from the API called.</param>
        /// <param name="metadata">The metadata contained in the response object returned from the API called.</param>
        /// </summary>
        public static void logResponse(String bwsApiName, String code, ResponseMetadata metadata)
        {
            logMessage("...{0} returned \"{1}\"", bwsApiName, code);
            if (metadata != null)
            {
                /* 
                 * Converting response.metadata.executionTime (which is in nano-seconds) into seconds by 
                 * multiplying it by 10^-9.
                 */
                logMessage("Execution Time: {0:0.0000} seconds", (metadata.executionTime * Math.Pow(10, -9)));
                logMessage("Request UID: {0}", metadata.requestUid);
            }
        }

        /// <summary>
        /// The Main function.
        /// </summary>
        static int Main(string[] args)
        {
            startTime.Start();
            // Return codes.
            const int success = 0;
            const int failure = 1;
            int returnCode = success;

            /* 
             * Flags that are used to determine whether or not 
             * CreateUser() and DisplayUserDetails() get called.
             */
            bool createNewUser = false;
            bool displayUserDetails = true;

            // Hostname to use when connecting to web service.        
            BWSHostName = "<BWSHostName>"; // e.g. BWSHostName = "server01.yourcompany.net".        
            Username = "<username>"; // e.g. Username = "admin".        
            Password = "<password>"; // e.g. Password = "password".

            // Email address used to create a new user with the createUsers() API call.
            CreateNewUserEmail = "\"user01@example.net\"";

            // Email address used to identify the user to find with the getUsersDetail() API call.
            DisplayUserDetailsEmail = "\"user01@example.net\"";

            /* 
             * BWS Host certificate must be installed on the client machine before running this sample code, otherwise
             * a SSL/TLS secure channel error will be thrown. For more information, see the BlackBerry Web Services for
             * Enterprise Administration For Microsoft .NET Developers Getting Started Guide.
             */
            try
            {
                logMessage("Initializing web services...");
                if (Setup())
                {
                    /* 
                     * Demonstrate call to bwsService.getSystemInfo().
                     * This is also the first authenticated call in the client application.
                     */
                    logMessage("Getting system information...");
                    if (GetSystemInfo())
                    {
                        if (createNewUser)
                        {
                            logMessage("Creating a user...");

                            // Demonstrate call to bwsService.createUsers() API.
                            if (!CreateUser())
                            {
                                logMessage("Error: CreateUser() failed");
                                returnCode = failure;
                            }
                        }

                        if (displayUserDetails)
                        {
                            logMessage("Displaying a user's details...");

                            // Demonstrate call to bwsService.getUsers() and bwsService.getUsersDetail() APIs.
                            if (!DisplayUserDetails())
                            {
                                logMessage("Error: DisplayUserDetails() failed");
                                returnCode = failure;
                            }
                        }
                    }
                    else
                    {
                        logMessage("Error: GetSystemInfo() failed");
                        returnCode = failure;
                    }
                }
                else
                {
                    logMessage("Error: Setup() failed");
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