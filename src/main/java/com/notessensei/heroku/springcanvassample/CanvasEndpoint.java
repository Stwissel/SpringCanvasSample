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
import org.springframework.ui.Model;
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

    @RequestMapping(value = "/sfdcauth", method = RequestMethod.POST)
    public ResponseEntity<String> canvasDefaultPost(final String endPoint, final Model model, final HttpSession session,
            final HttpServletRequest request,
            final HttpServletResponse response) {
        return this.canvasPost(null, model, session, request, response);
    }

    @RequestMapping(value = "/sfdcauth/{endpoint}", method = RequestMethod.POST)
    public ResponseEntity<String> canvasPost(@PathVariable(name = "endpoint", required = false) final String endPoint,
            final Model model,
            final HttpSession session, final HttpServletRequest request,
            final HttpServletResponse response) {

        final String signedRequest = request.getParameter("signed_request");
        final String redirectTo = (endPoint == null) ? "/" : "/" + endPoint;

        if (signedRequest == null) {
            return new ResponseEntity<>("signed_request missing", HttpStatus.BAD_REQUEST);
        }

        try {
            final CanvasAuthentication auth = CanvasAuthentication.create(request, signedRequest);
            if ((auth != null) && auth.isAuthenticated()) {
                // The canvas request was valid, we add Header and Token
                auth.addJwtToResponse(session, request, response);
                final HttpHeaders headers = new HttpHeaders();
                model.addAttribute("Location", redirectTo);
                //headers.add("Location", redirectTo);
                return new ResponseEntity<String>(this.getHTML(redirectTo), headers, HttpStatus.OK);
            }

        } catch (final Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("signed_request invalid:"+e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        // If we got here - it failed!
        return new ResponseEntity<>("Authorization failed", HttpStatus.UNAUTHORIZED);

    }

    private String getHTML(String redirectTo) {
        // TODO Replace with Mustache
        StringBuilder result = new StringBuilder();
       result.append("<!DOCTYPE html>\n");
       result.append("<html xmlns=\"http://www.w3.org/1999/xhtml\">\n");
       result.append("<head>\n");
       result.append("<title>Spring and Canvas</title>\n");
       result.append("<body>\n");
       result.append("<a href=\""+redirectTo+"\">{{Location}}</a>\n");
       result.append("<script type=\"text/javaScript\">\n");
       result.append("alert(\""+redirectTo+"\");\n");
       result.append("window.location.url='"+redirectTo+"';");
       result.append("</script>\n");
       result.append("</body>\n");
       result.append("</html>");
        return result.toString();
    }
}
