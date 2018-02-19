/** ========================================================================= *
 * Copyright (C)  2017, 2018 Salesforce Inc ( http://www.salesforce.com/      *
 *                            All rights reserved.                            *
 *                                                                            *
 *  @author     Stephan H. Wissel (stw) <swissel@salesforce.com>              *
 *                                       @notessensei                         *
 * @version     1.0                                                           *
 * ========================================================================== *
 *                                                                            *
 * Licensed under the  Apache License, Version 2.0  (the "License").  You may *
 * not use this file except in compliance with the License.  You may obtain a *
 * copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>.       *
 *                                                                            *
 * Unless  required  by applicable  law or  agreed  to  in writing,  software *
 * distributed under the License is distributed on an  "AS IS" BASIS, WITHOUT *
 * WARRANTIES OR  CONDITIONS OF ANY KIND, either express or implied.  See the *
 * License for the  specific language  governing permissions  and limitations *
 * under the License.                                                         *
 *                                                                            *
 * ========================================================================== *
 */
package com.notessensei.heroku.springcanvassample.security;

import java.util.Date;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

/**
 * Configuration values we read from the environment
 * 
 * @author swissel
 *
 */
public enum Config {

    PARAMS;

    // Values we get from the environment
    private final String secret;
    private final String sfdcSecret;
    private long         expirationTime = 864000_000; // 10 days

    private Config() {
        // Load from environment
        this.secret = (System.getenv("JWT_SECRET") == null)
                ? UUID.randomUUID().toString() + UUID.randomUUID().toString()
                : System.getenv("JWT_SECRET");
        this.sfdcSecret = (System.getenv("SDFC_SECRET") == null)
                ? UUID.randomUUID().toString() + UUID.randomUUID().toString()
                : System.getenv("SDFC_SECRET");
        final String timeCandidate = System.getenv("EXPIRATION_TIME");
        if (timeCandidate != null) {
            try {
                this.expirationTime = Long.parseLong(timeCandidate);
            } catch (final NumberFormatException nfe) {
                nfe.printStackTrace();
            }
        } else {
            this.expirationTime = 3600_000L; // 1 hour
        }

    }

    public int getCookieLifespan() {
        int result = 3600; // 1h
        try {
            result = Math.toIntExact(this.expirationTime / 1000);
        } catch (final Exception e) {
            // No handling, it will default to 1h
        }
        return result;
    }

    public Date getExpirationTime() {
        return new Date(System.currentTimeMillis() + this.expirationTime);
    }

    public byte[] getSecret() {
        return this.secret.getBytes();
    }

    public String getSfdcSecret() {
        return this.sfdcSecret;
    }

    /**
     * Convenience method for local debugging
     * allows skipping of signature verification
     * when running on localhost and environment parameter is set
     * 
     * @param request HTTP request to extract server name
     * @return true if insecure is acceptable
     */
    public boolean allowInsecureDebugOperation(HttpServletRequest request) {
        final String srv = request.getServerName().toLowerCase();
        if (!"localhost".equals(srv) && !"127.0.0.1".equals(srv) && !"::1".equals(srv)) {
            String insecure = System.getenv("INSECURE_DEBUG");
            return  insecure != null && "true".equalsIgnoreCase(insecure); 
        }
        return false;
    }

}
