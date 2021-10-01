# BWS Code Samples Repository 

The _**BWS-CodeSamples**_ repository holds code samples that demonstrate how to use the BlackBerry Web Services for Enterprise Administration API.

All APIs shared in this repository are Open Source under the  [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)

**To contribute code to this repository you must be signed up as an [official contributor](http://blackberry.github.com/howToContribute.html).**

## Code Organization

- Each sample added to the repository is available in both Java and C#. As of 10.2, some samples are also available for PowerShell.
- Samples for 10.2 have different sets of output for both BDS and UDS.
- To run the AuthenticationSample.java app, make sure that the project also includes Krb5LoginModuleConfiguration.java and ServiceTicketGenerator.java as separate files.

## BES12 and BlackBerry UEM Samples
The samples in this repository have been tested with both BES12 and BlackBerry UEM. In the samples, any references to BES12 are interchangeable with BlackBerry UEM.

In BES12 and BlackBerry UEM, SSO authentication is not supported. The AuthenticationSample apps still include this functionality for compatibility with BES10.

### C&#35;

AuthenticationSample
 - AuthenticationSample.cs - .NET code sample for authentication methods
 - AuthenticationSample.ConsoleBES12.txt - Output for AuthenticationSample.cs
 
SampleBwsClient
 - SampleBwsClient.cs - .NET code sample for creating a user
 - SampleBwsClient.ConsoleBES12.txt - Output for SampleBwsClient.cs

### Java 

AuthenticationSample
 - AuthenticationSample.java - Java code sample for the authentication methods
 - AuthenticationSample.ConsoleBES12.txt - Output for AuthenticationSample.java
 - Krb5LoginModuleConfiguration.java - A resource for AuthenticationSample.java
 - ServiceTicketGenerator.java - A resource for AuthenticationSample.java
 
SampleBwsClient
 - SampleBwsClient.java - Java code sample for creating a user
 - SampleBwsClient.ConsoleBES12.txt - Output for SampleBwsClient.java

### PowerShell

SampleBwsClient
 - SampleBwsClient.ps1 - PowerShell code sample for creating a user
 - SampleBwsClient.ConsoleBES12.txt - Output for SampleBwsClient.ps1
 

## 10.2 Samples

### C&#35;

AuthenticationSample
 - AuthenticationSample.cs - .NET code sample for authentication methods
 - AuthenticationSample_CS.ConsoleBDS.text - Output for AuthenticationSample.cs (BDS)
 - AuthenticationSample_CS.ConsoleUDS.text - Output for AuthenticationSample.cs (UDS)
 
SampleBwsClient
 - SampleBwsClient.cs - .NET code sample for creating a user
 - SampleBwsClient_CS.ConsoleBDS.txt - Output for SampleBwsClient.cs (BDS)
 - SampleBwsClient_CS.ConsoleUDS.txt - Output for SampleBwsClient.cs (UDS)

### Java 

AuthenticationSample
 - AuthenticationSample.java - Java code sample for authentication methods
 - AuthenticationSample_Java.ConsoleBDS.txt - Output for AuthenticationSample.java (BDS)
 - AuthenticationSample_Java.ConsoleUDS.txt - Output for AuthenticationSample.java (UDS)
 - Krb5LoginModuleConfiguration.java - A resource for AuthenticationSample.java
 - ServiceTicketGenerator.java - A resource for AuthenticationSample.java
 
SampleBwsClient
 - SampleBwsClient.java - Java code sample for creating a user
 - SampleBwsClient_Java.ConsoleBDS.txt - Output for SampleBwsClient.java (BDS)
 - SampleBwsClient_Java.ConsoleUDS.txt - Output for SampleBwsClient.java (UDS)

### PowerShell

SampleBwsClient
 - SampleBwsClient.ps1 - PowerShell code sample for creating a user
 - SampleBwsClient_Output.txt - Output for SampleBwsClient.ps1

## 10.1.3 and earlier Samples

### C&#35;

AuthenticationSample
 - AuthenticationSample.cs - .NET code sample for authentication methods
 - AuthenticationSample_CS.Console.text - Output for AuthenticationSample.cs
 
SampleBwsClient
 - SampleBwsClient.cs - .NET code sample for creating a user
 - SampleBwsClient_CS.Console.txt - Output for SampleBwsClient.cs
 
### Java

AuthenticationSample
 - AuthenticationSample.java - Java code sample for authentication methods
 - AuthenticationSample_Java.Console.txt - Output for AuthenticationSample.java
 - Krb5LoginModuleConfiguration.java - A resource for AuthenticationSample.java
 - ServiceTicketGenerator.java - A resource for AuthenticationSample.java

SampleBwsClient
 - SampleBwsClient.java - Java code sample for creating a user
 - SampleBwsClient_Java.Console.txt - Output for SampleBwsClient.java

### Running the samples

 - Set up your development environment by following the instructions in the BlackBerry Web Services Getting Started guide. You can find Getting Started Guides for Java and .NET at <a href="http://docs.blackberry.com/en/admin/subcategories/?userType=2&category=BlackBerry+Web+Services&subCategory=BlackBerry+Web+Services+for+BlackBerry+Enterprise+Service+10">docs.blackberry.com/BWSBES10</a>
 - For .NET projects, verify that your project includes the System.Web.Services reference.
 - If you want to use single sign-on authentication, reduce the restrictions of Windows UAC or turn off Windows UAC. Then, in the Registry Editor, in the following location, create a DWORD value named “allowtgtsessionkey” and assign it a value of 1:
 -- Windows 7, Windows Vista, Windows Server: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters
 -- Windows XP: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos

 
**Repository Committers** 

* [Colin Fullerton](https://github.com/cfullerton123)
* [Andrew Karger](https://github.com/akarger)

## Bug Reporting and Feature Requests

If you find a bug in a sample, or have an enhancement request, simply file an [Issue](https://github.com/blackberry/BWS-Samples/issues) for the sample and send a message (via github messages) to the sample Author(s) to let them know that you have filed an [Issue](https://github.com/blackberry/BWS-Samples/issues).

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

