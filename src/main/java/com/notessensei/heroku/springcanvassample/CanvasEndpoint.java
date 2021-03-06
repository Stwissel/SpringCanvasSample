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
package com.notessensei.heroku.springcanvassample;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.notessensei.heroku.springcanvassample.security.CanvasAuthentication;

/**
 * The Spring endpoint that accepts a Canvas Post from Salesforce and returns a
 * JWT and sends the user to the page with an actual payload
 *
 * @author swissel
 *
 */
@Controller
public class CanvasEndpoint {

    /**
     * Authentication to the application by a Canvas post with redirection to
     * the endpoint that actually provides the data requested
     *
     * @param endPoint
     *            - the endpoint to reach. Needs to be defined elsewhere to be
     *            valid (see HelloWorld for /hw)
     * @param session
     *            - HttpSession
     * @param request
     *            - HttpRequest
     * @param response
     *            - HttpResponse
     * @return - A response entity with a 303 or 400 status
     */
    @RequestMapping(value = "/sfdcauth/{endpoint}", method = RequestMethod.POST)
    public ResponseEntity<String> canvasPost(@PathVariable(name = "endpoint", required = false) final String endPoint,
            final HttpSession session, final HttpServletRequest request,
            final HttpServletResponse response) {

        final String signedRequest = request.getParameter("signed_request");
        final String redirectTo = ((endPoint == null) || "".equals(endPoint)) ? "/" : "/" + endPoint;

        if (signedRequest == null) {
            return new ResponseEntity<>("signed_request missing", HttpStatus.BAD_REQUEST);
        }

        try {
            final CanvasAuthentication auth = CanvasAuthentication.create(request, signedRequest);
            if ((auth != null) && auth.isAuthenticated()) {
                // The canvas request was valid, we add Header and Token
                final String token = auth.getJwtToken();
                CanvasAuthentication.addJwtCookie(session, request, response, token);

                // Prepare the header for the redirect to actual payload
                final HttpHeaders headers = new HttpHeaders();
                headers.add("Location", redirectTo);
                return new ResponseEntity<String>(redirectTo, headers, HttpStatus.SEE_OTHER);
            }

        } catch (final Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("signed_request invalid:" + e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        // If we got here - it failed!
        return new ResponseEntity<>("Authorization failed", HttpStatus.UNAUTHORIZED);

    }

}
