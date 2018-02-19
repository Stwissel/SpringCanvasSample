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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * @author swissel
 *
 */
public class CanvasAuthorizationFilter extends BasicAuthenticationFilter {

    public CanvasAuthorizationFilter(final AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal(javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain)
            throws IOException, ServletException {

        final String jwtCookie = this.getJwtCookie(request);

        // Check if we have a JWT we can process
        if ((jwtCookie != null) && !"null".equals(jwtCookie)) {
            final Authentication authentication = this.extractAuthentication(jwtCookie);
            if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // Put the cookie back
            CanvasAuthentication.addJwtCookie(request, response, jwtCookie);
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Extract credentials from a jwtString
     *
     * @param jwtHeader
     *            header might be null
     * @param jwtCookie
     *            might be null, but not both
     * @return an Authentication Toke
     */
    private Authentication extractAuthentication(final String jwtCookie) {
        // Cookie is prefered to header
        Authentication result = null;
        String user = null;
        final Collection<GrantedAuthority> roles = new ArrayList<>();
        // Now get user and claims (roles)
        try {
            final Claims claims = Jwts.parser()
                    .setSigningKey(Config.PARAMS.getSecret())
                    .parseClaimsJws(jwtCookie)
                    .getBody();
            for (final Entry<String, Object> entry : claims.entrySet()) {
                if (entry.getKey().equals(SecurityConstants.USER_NAME_CLAIM)) {
                    user = String.valueOf(entry.getValue());
                } else {
                    final String roleCandidate = String.valueOf(entry.getValue());
                    if (roleCandidate.startsWith(SecurityConstants.ROLE_PREFIX)) {
                        roles.add(new CanvasGrantedAuthority(
                                roleCandidate));
                    } else {
                        // TODO: other claims here?
                    }
                }
            }

            if (user != null) {
                result = new UsernamePasswordAuthenticationToken(user, UUID.randomUUID().toString(), roles);
            }

        } catch (final Exception e) {
            e.printStackTrace();
            result = null;
        }
        return result;
    }

    /**
     * Extract the cookie we need from the request
     *
     * @param request
     *            HTTP Request
     * @return a cookie or null
     */
    private String getJwtCookie(final HttpServletRequest request) {
        String result = null;
        String resultCandidate = null;

        // First we look in the session
        Object o = request.getSession().getAttribute(SecurityConstants.COOKIE_ATTRIBUTE);
        if (o != null) {
            result = String.valueOf(o);
            System.out.println("Session JWT found");
        } else {
            final Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (int i = 0; i < cookies.length; i++) {
                    final Cookie currentCookie = cookies[i];
                    if (currentCookie.getName().equals(SecurityConstants.COOKIE_NAME)) {
                        resultCandidate = currentCookie.getValue();
                        break;
                    }
                }
            }
        }
        if (resultCandidate != null) {
           // result = new String(new Base64().decode(resultCandidate.getBytes()));
           result = resultCandidate; 
        }

        return result;
    }
}
