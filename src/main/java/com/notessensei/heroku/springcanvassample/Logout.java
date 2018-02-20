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

import java.util.Enumeration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 *
 * The unavoidable HelloWorld example - Also gives an admin access to the
 * metrics endpoint
 *
 * @author swissel
 *
 */
@Controller
public class Logout {

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String index(final HttpSession session, final HttpServletRequest request, final HttpServletResponse response) {

        // Clear the context
        SecurityContextHolder.getContext().setAuthentication(null);
        SecurityContextHolder.clearContext();

        // Clear cookies
        this.killCookies(request, response);

        // Clear the attributes
        final Enumeration<String> e = session.getAttributeNames();
        while (e.hasMoreElements()) {
            final String attr = e.nextElement();
            session.setAttribute(attr, null);
        }
        session.invalidate();

        return "logout";
    }

    private void killCookies(final HttpServletRequest request, final HttpServletResponse response) {
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                cookies[i].setMaxAge(0);
                response.addCookie(cookies[i]);
            }
        }
    }
}
