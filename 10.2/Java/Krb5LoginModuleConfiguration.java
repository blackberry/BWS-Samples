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

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;

/*
 * Krb5LoginModuleConfiguration.java
 *
 * A class to generate the required configuration for using Kerberos authentication.
 */

public class Krb5LoginModuleConfiguration extends Configuration
{
    public static final String KERBEROS_CONFIGURATION_NAME = "SignedOnUserLoginContext";
    
    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name)
    {
        if (!KERBEROS_CONFIGURATION_NAME.equals(name))
        {
            return null;
        }
        
        AppConfigurationEntry[] appConfigurationEntries = createAppConfigurationEntities();
        return appConfigurationEntries;
    }
    
    private AppConfigurationEntry[] createAppConfigurationEntities()
    {
        AppConfigurationEntry[] appConfigurationEntries = new AppConfigurationEntry[1];
        Map<String, String> options = new HashMap<String, String>();
        options.put("useTicketCache", "true");
        options.put("doNotPrompt", "true");
        appConfigurationEntries[0] = new AppConfigurationEntry(
                "com.sun.security.auth.module.Krb5LoginModule", LoginModuleControlFlag.REQUIRED,
                options);
        return appConfigurationEntries;
    }
}
