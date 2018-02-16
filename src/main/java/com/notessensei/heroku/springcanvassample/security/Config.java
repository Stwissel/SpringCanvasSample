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

/**
 * Configuration values we read from the environment
 * @author swissel
 *
 */
public enum Config {

    PARAMS;
    
    // Values we get from the environment
    private String secret = null;
    private long expirationTime = 864000_000; // 10 days
    
    private Config() {
        // Load from environment
        this.secret = System.getenv("JWT_SECRET");
        String timeCandidate = System.getenv("EXPIRATION_TIME");
        if (timeCandidate != null) {
            try {
                this.expirationTime = Long.parseLong(timeCandidate);
            } catch (NumberFormatException nfe) {
                nfe.printStackTrace();
            }
        }
        // Catch missing values
        if (this.secret == null) {
            this.secret = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        }
        if (this.expirationTime == 0) {
            this.expirationTime = 3600_000L; // 1 hour
        }
        
    }

    public byte[] getSecret() {
        return this.secret.getBytes();
    }

    public Date getExpirationTime() {
        return new Date(System.currentTimeMillis() + this.expirationTime);
    }
    
}
