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

import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author swissel
 *
 */
@Controller
@RequestMapping("/login")
public class AdminLoginController {

    @GetMapping
    public String loginForm(final HttpServletResponse response) {
        Cookie bla = new Cookie("Bla","blaaaah");
        bla.setHttpOnly(true);
        bla.setSecure(true);
        bla.setPath("/");
        response.addCookie(bla);
        return "login";
    }

    @PostMapping
    public ResponseEntity<String> authenticate(@RequestParam Map<String,String> params, /*HttpSession session , */ HttpServletRequest request, HttpServletResponse response) {

        CanvasAuthentication result = null;

        try {

        String userName = params.get("username");
        String password = params.get("password");

        if (userName == null || password == null) {
            throw new SecurityException("Username or password missing");
        }

        if (!Config.PARAMS.adminIsValid(userName,password) ) {
            throw new SecurityException("Username or password missing");
        }

        result = CanvasAuthentication.createAdminAccess(userName, password);
        result.addJwtToResponse(/*session,*/ request, response);
        } catch (Exception e) {

        }
        if (result != null) {
         SecurityContextHolder.getContext().setAuthentication(result);
         final HttpHeaders headers = new HttpHeaders();
         headers.add("Location", "/hw");
         return new ResponseEntity<>("Loading...", headers, HttpStatus.FOUND);
        }
        return new ResponseEntity<>("/login", HttpStatus.UNAUTHORIZED);
    }

}
