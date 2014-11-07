package codesample;

/* 
 * Copyright (c) 2013 BlackBerry. 
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

import java.io.IOException;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceException;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.HTTPException;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;

import com.rim.ws.enterprise.admin.Authenticator;
import com.rim.ws.enterprise.admin.BWS;
import com.rim.ws.enterprise.admin.BWSService;
import com.rim.ws.enterprise.admin.BWSUtil;
import com.rim.ws.enterprise.admin.BWSUtilService;
import com.rim.ws.enterprise.admin.CredentialType;
import com.rim.ws.enterprise.admin.EchoRequest;
import com.rim.ws.enterprise.admin.EchoResponse;
import com.rim.ws.enterprise.admin.GetAuthenticatorsRequest;
import com.rim.ws.enterprise.admin.GetAuthenticatorsResponse;
import com.rim.ws.enterprise.admin.GetEncodedUsernameRequest;
import com.rim.ws.enterprise.admin.GetEncodedUsernameResponse;
import com.rim.ws.enterprise.admin.GetSystemInfoRequest;
import com.rim.ws.enterprise.admin.GetSystemInfoResponse;
import com.rim.ws.enterprise.admin.Property;
import com.rim.ws.enterprise.admin.RequestMetadata;
import com.rim.ws.enterprise.admin.ResponseMetadata;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

/*
 * AuthenticationSample.java
 *
 * A program that demonstrates the different methods of authentication for 
 * BlackBerry Web Services (BWS) for Enterprise Administration APIs.
 *
 * This sample program demonstrates how to make an authenticated API call
 * using one of three options:
 *  1)  BlackBerry Administration Service credentials
 *  2)  Active Directory Credentials
 *  3)  Single Sign On using the currently logged in user's credentials

 * Tested with Apache CXF 2.7.3, recommended to use Apache CXF 2.7.3 or later.
 *
 * This program was tested against the BlackBerry Enterprise Service 10 version 10.2.0.
 */

public class AuthenticationSample {
    // Values used in log messages.
    final private static long NANOSECONDS_IN_A_MILLISECOND = 1000000L;
    final private static float NANOSECONDS_IN_A_SECOND = 1000 * NANOSECONDS_IN_A_MILLISECOND;
    final private static long startTime = System.nanoTime();

    // Web service stubs.
    private static BWSService _bwsService;
    private static BWS _bws;
    private static BWSUtilService _bwsUtilService;
    private static BWSUtil _bwsUtil;

    // The request Metadata information. This is the version of the WSDL used to generate the proxy,
    // not the version of the server.
    private final static String CLIENT_VERSION = "<Client Version>"; // e.g. CLIENT_VERSION = "10.2.0"

    // The enum used to determine the current server type.
    private enum ServerType { Unknown, BDS, UDS };

    // Enum used to determine if the server used in this execution is BDS or UDS
    private static ServerType _serverType = ServerType.Unknown;
    /*
     * To use a different locale, call getLocales() in the BWSUtilService web service to see which locales are
     * supported.
     */
    private final static String LOCALE = "en_US";
    private final static String ORG_UID = "0";
    private final static RequestMetadata REQUEST_METADATA = new RequestMetadata();

    /*****************************************************************************************************************
     * 
     * Get the authenticator object for the authenticator name.
     * 
     * @param authenticatorName A string containing the name of the desired authenticator.
     * @return Returns the requested authenticator if it is found, null otherwise.
     * 
     ***************************************************************************************************************** 
     */
    public static Authenticator getAuthenticator(String authenticatorName) throws WebServiceException {
        final String METHOD_NAME = "getAuthenticator()";
        final String BWS_API_NAME = "_bwsUtil.getAuthenticators()";
        logMessage("Entering %s", METHOD_NAME);
        Authenticator returnValue = null;

        GetAuthenticatorsRequest request = new GetAuthenticatorsRequest();
        request.setMetadata(REQUEST_METADATA);

        GetAuthenticatorsResponse response = null;
        try {
            logRequest(BWS_API_NAME);
            response = _bwsUtil.getAuthenticators(request);
            logResponse(BWS_API_NAME, response.getReturnStatus().getCode(), response.getMetadata());
        } catch (WebServiceException e) {
            // Log and re-throw exception.
            logMessage("Exiting %s with exception \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        }

        if (response.getReturnStatus().getCode().equals("SUCCESS")) {
            if (response.getAuthenticators() != null && !response.getAuthenticators().isEmpty()) {
                for (Authenticator authenticator : response.getAuthenticators()) {
                    if (authenticator.getName().equalsIgnoreCase(authenticatorName)) {
                        returnValue = authenticator;
                        break;
                    }
                }

                if (returnValue == null) {
                    logMessage("Could not find \"%s\" in GetAuthenticatorsResponse", authenticatorName);
                }
            } else {
                logMessage("No authenticators in GetAuthenticatorsResponse");
            }
        } else {
            logMessage("Error Message: \"%s\"", response.getReturnStatus().getMessage());
        }

        logMessage("Exiting %s with %s", METHOD_NAME, returnValue == null ? "\"null\""
                : "Authenticator object (Name \"" + returnValue.getName() + "\")");
        return returnValue;
    }

    /*****************************************************************************************************************
     * 
     * Get the encoded username required to authenticate user to BWS.
     * 
     * @return Returns a string containing the encoded username if successful, and null otherwise.
     * 
     ***************************************************************************************************************** 
     */
    public static String getEncodedUserName(String username, Authenticator authenticator,
            CredentialType credentialType, String domain) throws WebServiceException {
        final String METHOD_NAME = "getEncodedUserName()";
        final String BWS_API_NAME = "_bwsUtil.getEncodedUsername()";
        logMessage("Entering %s", METHOD_NAME);
        String returnValue = null;

        GetEncodedUsernameRequest request = new GetEncodedUsernameRequest();
        request.setMetadata(REQUEST_METADATA);
        request.setUsername(username);
        request.setOrgUid(REQUEST_METADATA.getOrganizationUid());
        request.setAuthenticator(authenticator);

        request.setCredentialType(credentialType);
        request.setDomain(domain);

        GetEncodedUsernameResponse response = null;
        try {
            logRequest(BWS_API_NAME);
            response = _bwsUtil.getEncodedUsername(request);
            logResponse(BWS_API_NAME, response.getReturnStatus().getCode(), response.getMetadata());
        } catch (WebServiceException e) {
            // Log and re-throw exception.
            logMessage("Exiting %s with exception \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        }

        if (response.getReturnStatus().getCode().equals("SUCCESS")) {
            returnValue = response.getEncodedUsername();
        } else {
            logMessage("Error Message: \"%s\"", response.getReturnStatus().getMessage());
        }

        logMessage("Exiting %s", METHOD_NAME);
        return returnValue;
    }
    
    /*****************************************************************************************************************
     * 
     * Call bwsService.getSystemInfo() and set the _serverType member.
     * 
     ***************************************************************************************************************** 
     */
    public static void getSystemInfo() {
        final String METHOD_NAME = "getSystemInfo()";
        final String BWS_API_NAME = "_bws.getSystemInfo()";

        logMessage("Entering %s", METHOD_NAME);

        GetSystemInfoRequest request = new GetSystemInfoRequest();
        request.setLoadAuthenticatedUserProperties(false);
        request.setMetadata(REQUEST_METADATA);

        GetSystemInfoResponse response = null;

        /*
         * The try catch block here is used to illustrate how to handle a specific type of exception.
         * For example, in this case we check to see if the error was caused by invalid credentials.
         */
        try {
            logRequest(BWS_API_NAME);
            response = _bws.getSystemInfo(request);
            logResponse(BWS_API_NAME, response.getReturnStatus().getCode(), response.getMetadata());
        } catch (WebServiceException e) {
            if (e.getCause() instanceof HTTPException) {
                HTTPException httpException = (HTTPException) e.getCause();
                // Handle authentication failure.
                if (httpException != null && httpException.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                    logMessage("Failed to authenticate with the BWS web service");
                }
            }

            // Log and re-throw exception.
            logMessage("Exiting %s with exception \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        }

        if (response.getReturnStatus().getCode().equals("SUCCESS")) {
            if (response.getProperties() != null && !response.getProperties().isEmpty()) {
                for (Property property : response.getProperties()) {
                    if (property.getName().equalsIgnoreCase("BWS Version")) {
                        _serverType = ServerType.BDS;
                        break;
                    }
                    if (property.getName().equalsIgnoreCase("BUDS Version")) {
                        _serverType = ServerType.UDS;
                        break;
                    }
                }
            }
            else {
                logMessage("No properties in response");
            }
        }
        else {
            System.err.format("Error: Code: \"%s\", Message: \"%s\"%n", response.getReturnStatus().getCode(), response
                    .getReturnStatus().getMessage());
        }

        logMessage("Exiting %s", METHOD_NAME);
    }

    /*****************************************************************************************************************
     * 
     * Perform a call to _bws.echo().
     * 
     * @return Returns true if echo is successful, and false otherwise.
     * 
     ***************************************************************************************************************** 
     */
    public static boolean echo() throws WebServiceException {
        final String METHOD_NAME = "echo()";
        final String BWS_API_NAME = "_bws.echo()";
        logMessage("Entering %s", METHOD_NAME);

        boolean returnValue = true;

        EchoRequest request = new EchoRequest();
        EchoResponse response = null;

        request.setMetadata(REQUEST_METADATA);
        request.setText("Hello World!");

        try {
            logRequest(BWS_API_NAME);
            response = _bws.echo(request);
            logResponse(BWS_API_NAME, response.getReturnStatus().getCode(), response.getMetadata());
        } catch (WebServiceException e) {
            if (e.getCause() instanceof HTTPException) {
                HTTPException httpException = (HTTPException) e.getCause();
                // Handle authentication failure.
                if (httpException != null && httpException.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                    returnValue = false;
                    logMessage("Failed to authenticate with the BWS web service");
                    logMessage("Exiting %s with value \"%s\"", METHOD_NAME, returnValue);
                    return returnValue;
                }
            }

            // Log and re-throw exception.
            logMessage("Exiting %s with exception \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        }

        logMessage("Exiting %s with value \"%s\"", METHOD_NAME, returnValue);
        return returnValue;
    }

    /*****************************************************************************************************************
     * 
     * Acquire the SPNEGO token for the BlackBerry Enterprise Service using the currently logged in user's credentials
     * and then Base 64 Encode the Token.
     * 
     * @param username The username of the current user.
     * @param domain The domain of the user and the BlackBerry Enterprise Server.
     * @param kerberosRealm The kerberos realm. It must be uppercase. It is usually equal to the uppercase of the
     *            domain.
     * @param bwsHostname The address of the BlackBerry Enterprise Server hosting BWS.
     * 
     * @return Returns the base 64 encoded SPNEGO token for the currently logged in user.
     * 
     *****************************************************************************************************************
     */
    public static String getBase64EncodedSpnegoToken(String username, String domain, String kerberosRealm,
            String bwsHostname) throws LoginException, PrivilegedActionException {
        String METHOD_NAME = "getBase64EncodedSpnegoToken";
        logMessage("Entering %s", METHOD_NAME);

        String returnValue = null;
        byte[] token = null;

        System.setProperty("java.security.krb5.realm", kerberosRealm);
        System.setProperty("java.security.krb5.kdc", domain);

        final String domainUsername = username + "@" + domain;
        final String servicePrincipal = "BASPLUGIN111/" + bwsHostname + "@" + kerberosRealm;

        final Subject nullSubject = null;
        final CallbackHandler nullCallbackHandler = null;
        Configuration config = new Krb5LoginModuleConfiguration();

        try {
            LoginContext loginContext = new LoginContext(Krb5LoginModuleConfiguration.KERBEROS_CONFIGURATION_NAME,
                    nullSubject, nullCallbackHandler, config);

            loginContext.login();

            Subject clientSubject = loginContext.getSubject();
            token = (byte[]) Subject.doAs(clientSubject, 
			        new ServiceTicketGenerator(domainUsername, servicePrincipal));

            loginContext.logout();
        } catch (LoginException e) {
            // Log and re-throw exception.
            logMessage("Exiting %s with LoginException \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        } catch (PrivilegedActionException e) {
            // Log and re-throw exception.
            logMessage("Exiting %s with PrivilegedActionException \"%s\"", METHOD_NAME, e.getMessage());
            throw e;
        }

        // encode the token using Base64 encoding before returning it
        if (token != null) {
            returnValue = Base64.encode(token);
        }

        logMessage("Exiting %s with %s", METHOD_NAME, returnValue == null ? "null" : "a token");
        return returnValue;
    }

    /*****************************************************************************************************************
     * 
     * Creates a string containing the elapsed time since the program started. The execution time will be reset to
     * 00:00.000 if the execution time exceeds an hour.
     * 
     * @return Returns the elapsed time from start of program.
     * 
     ***************************************************************************************************************** 
     */
    public static String logTime() {
        DateFormat dateFormat = new SimpleDateFormat("mm:ss.SSS");
        long timeDifference = System.nanoTime() - startTime;
        long dateTime = (timeDifference / NANOSECONDS_IN_A_MILLISECOND);
        String time = dateFormat.format(dateTime);
        return time;
    }

    /*****************************************************************************************************************
     * 
     * Prints a log message to stderr.
     * 
     * @param format A string which formats how args will be displayed in the message.
     * @param args List of objects to be displayed in the message.
     * 
     *****************************************************************************************************************
     */
    public static void logMessage(String format, Object... args) {
        // Change output stream if desired
        PrintStream logStream = System.err;
        logStream.format(logTime() + " " + format + "%n", args);
    }

    /*****************************************************************************************************************
     * 
     * Logs the calling of an API.
     * 
     *****************************************************************************************************************
     */
    public static void logRequest(String bwsApiName) {
        logMessage("Calling %s...", bwsApiName);
    }

    /*****************************************************************************************************************
     * 
     * Logs various information about an API response.
     * 
     *****************************************************************************************************************
     */
    public static void logResponse(String bwsApiName, String code, ResponseMetadata metadata) {
        logMessage("...%s returned \"%s\"", bwsApiName, code);
        if (metadata != null) {
            // Converting metadata.getExecutionTime() (which is in nano-seconds) into seconds
            logMessage("Execution Time: %.4f seconds", (metadata.getExecutionTime() / NANOSECONDS_IN_A_SECOND));

            logMessage("Request UID: %s", metadata.getRequestUid());
        }
    }

    /*****************************************************************************************************************
     * 
     * The main method.
     * 
     * @param args Not used.
     * @throws IOException If it fails to create log files.
     * 
     *****************************************************************************************************************
     */
    public static void main(String[] args) throws IOException {
        // Return codes
        final int SUCCESS = 0;
        final int FAILURE = 1;

        int returnCode = SUCCESS;

        // Hostname to use when connecting to web service. Must contain the fully qualified domain name.
        String bwsHostname = "<bwsHostname>"; // e.g. bwsHostname = "server01.example.net".

        // Port to use when connecting to web service. The same port is used to access the
        // webconsole.
        String bwsPort = "<bwsPort>"; // e.g. bwsPort = "38443".
        
        // Credential type used in the authentication process.
        CredentialType credentialType = new CredentialType();
        credentialType.setPASSWORD(true);
        credentialType.setValue("PASSWORD");
        
        /*
         * BWS Host certificate must be installed on the client machine before running this sample code, otherwise a
         * SSL/TLS secure channel error will be thrown. For more information, see the BlackBerry Web Services for
         * Enterprise Administration For Java Developers Getting Started Guide.
         * 
         * To test authentication populate the methods below with the appropriate credentials and information
         */

        // Select which authentication methods you would like to test by setting the variables to true
        boolean useAD = true; // Active Directory
        boolean useLDAP = false; // LDAP
        boolean useADSSO = true; // Active Directory with Single Sign On credentials

        try {
            if (bwsHostname.indexOf('.') < 1) {
                throw new Exception("Invalid bwsHostname format. Expected format is \"server01.example.net\"");
            }
            // bwsPort, if not null, must be a positive integer
            if (bwsPort != null) {
                int port = Integer.parseInt(bwsPort);

                if (port < 1) {
                    throw new Exception("Invalid bwsPort. Expecting a positive integer string or null");
                }
            }
            
            returnCode = (demonstrateBlackBerryAdministrationServiceAuthentication(bwsHostname, bwsPort, credentialType)) 
                    ? SUCCESS : FAILURE;
            logMessage("");
            if (useAD && returnCode == SUCCESS) {
                returnCode = (demonstrateActiveDirectoryAuthentication(bwsHostname, bwsPort, credentialType)) 
                    ? SUCCESS : FAILURE;
                logMessage("");
            }
            if (useLDAP && returnCode == SUCCESS) {
                returnCode = (demonstrateLDAPAuthentication(bwsHostname, bwsPort, credentialType)) ? SUCCESS : FAILURE;
                logMessage("");
            }
            if (useADSSO && returnCode == SUCCESS) {
                returnCode = (demonstrateActiveDirectorySSOAuthentication(bwsHostname, bwsPort)) ? SUCCESS : FAILURE;
                logMessage("");
            }
        } catch (Exception e) {
            logMessage("Exception: \"%s\"%n", e.getMessage());
            e.printStackTrace();
            returnCode = FAILURE;
        }

        System.err.format("Exiting sample.%nPress Enter to exit%n");
        System.in.read();

        System.exit(returnCode);
    }

    /*****************************************************************************************************************
     * Demonstrates BlackBerry Administration Service Authentication. Fields denoted by "<value>" must be manually set.
     * 
     * @return Returns true if authenticated successfully, false otherwise.
     ***************************************************************************************************************** 
     */
    private static boolean demonstrateBlackBerryAdministrationServiceAuthentication(String bwsHostname,
        	String bwsPort, CredentialType credentialType) {
        logMessage("Attempting BlackBerry Administration Service authentication");

        // The BlackBerry Administration Service Credentials to use
        String username = "<username>"; // e.g. username = "admin".
        String password = "<password>"; // e.g. password = "password".
        String authenticatorName = "BlackBerry Administration Service";
        String domain = null; // not needed

        return demonstrateBwsSetupAndAuthenticatedCall(bwsHostname, bwsPort, username, password,
                domain, authenticatorName, credentialType);
    }

    /*****************************************************************************************************************
     * Demonstrates Active Directory Authentication. Fields denoted by "<value>" must be manually set.
     * 
     * @return Returns true if authenticated successfully, false otherwise.
     ***************************************************************************************************************** 
     */
    private static boolean demonstrateActiveDirectoryAuthentication(String bwsHostname, String bwsPort, 
            CredentialType credentialType) {
        logMessage("Attempting Active Directory authentication");

        // The Active Directory Credentials to use
        String username = "<username>"; // e.g. username = "admin".
        String password = "<password>"; // e.g. password = "password".
        String authenticatorName = "Active Directory";
        // Only BDS requires domain for authentication
        String activeDirectoryDomain = null;
        if(_serverType == ServerType.BDS){
        	activeDirectoryDomain = "<domain>"; // e.g. activeDirectoryDomain = "example.net"
        }

        return demonstrateBwsSetupAndAuthenticatedCall(bwsHostname, bwsPort, username, password,
                activeDirectoryDomain, authenticatorName, credentialType);
    }
    
    /*****************************************************************************************************************
     * Demonstrates LDAP Authentication. Fields denoted by "<value>" must be manually set.
     * 
     * @return Returns true if authenticated successfully, false otherwise.
     ***************************************************************************************************************** 
     */
    private static boolean demonstrateLDAPAuthentication(String bwsHostname, String bwsPort, 
            CredentialType credentialType) {
        logMessage("Attempting LDAP authentication");

        // The LDAP Credentials to use
        String username = "<username>"; // e.g. username = "admin".
        String password = "<password>"; // e.g. password = "password".
        String authenticatorName = "LDAP";
        String domain = null; // not needed

        return demonstrateBwsSetupAndAuthenticatedCall(bwsHostname, bwsPort, username, password,
                domain, authenticatorName, credentialType);
    }
    
    /*****************************************************************************************************************
     * Demonstrates Active Directory Authentication using Single Sign On Credentials. The sample below automatically 
     * acquires the username and domain from the currently logged in user's environment.
     * @return Returns true if authenticated successfully, false otherwise.
     *****************************************************************************************************************
     */
    private static boolean demonstrateActiveDirectorySSOAuthentication(String bwsHostname, String bwsPort)
            throws WebServiceException {
        logMessage("Attempting Active Directory authentication using SSO credentials");
        /*
         * The 'allowtgtsession' registry key must be set before using SSO, otherwise errors will be thrown. For more
         * information, see the BlackBerry Web Services for Enterprise Administration For Java Developers Getting
         * Started Guide.
         * 
         * 
         * For more information about Kerberos and the Java GSSAPI see:
         * http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/single-signon.html and
         * http://web.mit.edu/kerberos/krb5-latest/doc
         */

        // The SSO Credentials to use. Automatically acquires the currently
        // logged in user and their Kerberos TGT (Ticket Granting Ticket)
        String username = System.getProperty("user.name");
        String password = null; // is populated by getBase64EncodedSPNEGOToken() below
        String authenticatorName = "Active Directory";
        String activeDirectoryDomain = System.getenv("USERDNSDOMAIN");
        CredentialType credentialType = new CredentialType();
        credentialType.setSSO(true);
        credentialType.setValue("SSO");
        
        logMessage("Username (case sensitive): %s", username);
        logMessage("Domain: %s", activeDirectoryDomain);

        String kerberosRealm = bwsHostname.substring(bwsHostname.indexOf('.') + 1).toUpperCase();

        try {
            try {
                password = getBase64EncodedSpnegoToken(username, activeDirectoryDomain, kerberosRealm, bwsHostname);
            } catch (Exception e) {
                logMessage("Exception: \"%s\"", e.getMessage());
            }
            // Only BDS requires domain for authentication
            if(_serverType != ServerType.BDS){
            	activeDirectoryDomain = null;
            }              
            if (password == null) {
                logMessage("Failed to retrieve SPNEGO Token for SSO.");
                return false;
            }
        } catch (WebServiceException e) {
            logMessage("Exception: \"%s\"", e.getMessage());
            throw e;
        }

        return demonstrateBwsSetupAndAuthenticatedCall(bwsHostname, bwsPort, username, password,
                activeDirectoryDomain, authenticatorName, credentialType);

    }

    /*****************************************************************************************************************
     * Tests if the passed in settings successfully authenticate against BWS.
     * 
     * @return Returns true if authenticated successfully, false otherwise.
     *****************************************************************************************************************
     */
    private static boolean demonstrateBwsSetupAndAuthenticatedCall(String bwsHostname, String bwsPort,
            String username, String password, String domain, String authenticatorName,
            CredentialType credentialType) throws WebServiceException {
        boolean returnCode = false;
        logMessage("Initializing web services...");
        if (setup(bwsHostname, bwsPort, username, password, authenticatorName, credentialType, domain)) {
            
            /*
             * It is anticipated that the first time through this method, _serverType will be unknown. So getSystemInfo()
             * will populate this value, which will be used in the subsequent demonstrate calls if required.
             */
            if(_serverType == ServerType.Unknown){
                getSystemInfo();
            }
            
            /*
             * Demonstrate authenticated call to _bws.echo() API.
             */
            logMessage("Attempting authenticated BWS call to echo()...");
            if (echo()) {
                logMessage("Authenticated call succeeded!");
                returnCode = true;
            } else {
                logMessage("Authenticated call failed!");
            }
        } else {
            logMessage("Error: setup() failed");
        }
        return returnCode;
    }

    /*****************************************************************************************************************
     * 
     * Initialize the BWS and BWSUtil services.
     * 
     * @return Returns true when the setup is successful, and false otherwise.
     * 
     ***************************************************************************************************************** 
     */
    private static boolean setup(String hostname, String bwsPort, String username, String password,
            String authenticatorName, CredentialType credentialType, String domain) {
        final String METHOD_NAME = "setup()";
        logMessage("Entering %s", METHOD_NAME);
        boolean returnValue = false;
        REQUEST_METADATA.setClientVersion(CLIENT_VERSION);
        REQUEST_METADATA.setLocale(LOCALE);
        REQUEST_METADATA.setOrganizationUid(ORG_UID);

        URL bwsServiceUrl = null;
        URL bwsUtilServiceUrl = null;

        try {
            // These are the URLs that point to the web services used for all calls.
            // e.g. with no port:
            // https://server01.example.net/enterprise/admin/ws
            // e.g. with port:
            // https://server01.example.net:38443/enterprise/admin/ws
            String port = "";

            if (bwsPort != null) {
                port = ":" + bwsPort;
            }

            bwsServiceUrl = new URL("https://" + hostname + port + "/enterprise/admin/ws");
            bwsUtilServiceUrl = new URL("https://" + hostname + port + "/enterprise/admin/util/ws");

        } catch (MalformedURLException e) {
            logMessage("Cannot initialize web service URLs");
            logMessage("Exiting %s with value \"%s\"", METHOD_NAME, returnValue);
            return returnValue;
        }

        // Initialize the BWS web service stubs that will be used for all calls.
        logMessage("Initializing BWS web service stub");
        QName serviceBWS = new QName("http://ws.rim.com/enterprise/admin", "BWSService");
        QName portBWS = new QName("http://ws.rim.com/enterprise/admin", "BWS");
        _bwsService = new BWSService(null, serviceBWS);
        _bwsService.addPort(portBWS, "http://schemas.xmlsoap.org/soap/", bwsServiceUrl.toString());
        _bws = _bwsService.getPort(portBWS, BWS.class);
        logMessage("BWS web service stub initialized");

        logMessage("Initializing BWSUtil web service stub");
        QName serviceUtil = new QName("http://ws.rim.com/enterprise/admin", "BWSUtilService");
        QName portUtil = new QName("http://ws.rim.com/enterprise/admin", "BWSUtil");
        _bwsUtilService = new BWSUtilService(null, serviceUtil);
        _bwsUtilService.addPort(portUtil, "http://schemas.xmlsoap.org/soap/", bwsUtilServiceUrl.toString());
        _bwsUtil = _bwsUtilService.getPort(portUtil, BWSUtil.class);
        logMessage("BWSUtil web service stub initialized");
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

        Authenticator authenticator = getAuthenticator(authenticatorName);
        if (authenticator != null) {
            String encodedUsername = getEncodedUserName(username, authenticator, credentialType, domain);
            if (encodedUsername != null && !encodedUsername.isEmpty()) {
                /*
                 * Set the HTTP basic authentication on the BWS service. BWSUtilService is a utility web service that
                 * does not require authentication.
                 */
                BindingProvider bp = (BindingProvider) _bws;
                bp.getRequestContext().put(BindingProvider.USERNAME_PROPERTY, encodedUsername);
                bp.getRequestContext().put(BindingProvider.PASSWORD_PROPERTY, password);

                returnValue = true;
            } else {
                logMessage("\"encodedUsername\" is null or empty");
            }
        } else {
            logMessage("\"authenticator\" is null");
        }

        logMessage("Exiting %s with value \"%s\"", METHOD_NAME, returnValue);
        return returnValue;
    }
}