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

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/*
 * ServiceTicketGenerator.java
 *
 * Uses the GSSAPI to establish a Kerberos-context to acquire a SPNEGO token for 
 * the BlackBerry Administration Service from the Kerberos Server. The run()
 * method is called by Subject.doAs() so it uses the subject's credentials when
 * communicating with Kerberos.
 */

public class ServiceTicketGenerator implements PrivilegedExceptionAction<byte[]>
{
    private String ntUserName;
    private String servicePrincipalName;
    
    public ServiceTicketGenerator(String ntUserName, String servicePrincipalName)
    {
        this.ntUserName = ntUserName;
        this.servicePrincipalName = servicePrincipalName;
    }
    
    @Override
    public byte[] run() throws Exception
    {
        byte[] spnegoToken = null;
        try
        {
            Oid kerberos5Oid = new Oid("1.2.840.113554.1.2.2");
            Oid defaultMechanism = null;
            
            GSSManager gssManager = GSSManager.getInstance();
            
            GSSName clientName = gssManager.createName(ntUserName, GSSName.NT_USER_NAME);
            GSSName serviceName = gssManager.createName(servicePrincipalName, defaultMechanism);
            
            GSSCredential clientCredentials = gssManager.createCredential(clientName,
                    GSSContext.DEFAULT_LIFETIME, kerberos5Oid, GSSCredential.INITIATE_ONLY);
            
            GSSContext gssContext = gssManager.createContext(serviceName, kerberos5Oid,
                    clientCredentials, GSSContext.DEFAULT_LIFETIME);
            
            gssContext.requestCredDeleg(false);
            gssContext.requestMutualAuth(false);
            
            spnegoToken = gssContext.initSecContext(new byte[0], 0, 0);
            
            gssContext.dispose();
            
            return spnegoToken;
            
        }
        catch (Exception ex)
        {
            throw new PrivilegedActionException(ex);
        }
    }
}
