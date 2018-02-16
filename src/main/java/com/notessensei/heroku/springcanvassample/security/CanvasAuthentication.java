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

import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Implements
 *
 * @author swissel
 *
 */
public class CanvasAuthentication implements Authentication {

	private static final long serialVersionUID = 1L;

	// TODO: Replace Object with the real thing
	public static CanvasAuthentication create(final Object sfdcCanvas) throws Exception {
		if (sfdcCanvas == null) {
			throw new Exception("Canvas request is missing");
		}
		return new CanvasAuthentication();
	}

	private String name;

	private final Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
	private boolean isAuthenticated;

	// TODO: remove this
	public CanvasAuthentication() {
		this.name = "Peter Pan";
		this.grantedAuthorities.add(new CanvasGrantedAuthority("ADMIN"));
		this.grantedAuthorities.add(new CanvasGrantedAuthority("USER"));
		this.isAuthenticated = true;
	}

	/**
	 * @see org.springframework.security.core.Authentication#getAuthorities()
	 */
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.grantedAuthorities;
	}

	/**
	 * @see org.springframework.security.core.Authentication#getCredentials()
	 */
	@Override
	public Object getCredentials() {
	    //FIXME: proper Value here
		return "SFDCRequest";
	}

	/**
	 * @see org.springframework.security.core.Authentication#getDetails()
	 */
	@Override
	public Object getDetails() {
		return null;
	}

	/**
	 * @see java.security.Principal#getName()
	 */
	@Override
	public String getName() {
		return this.name;
	}

	/**
	 * @see org.springframework.security.core.Authentication#getPrincipal()
	 */
	@Override
	public User getPrincipal() {
		User result = new User(this.getName(), UUID.randomUUID().toString(), this.getAuthorities());
		return result;
	}

	/**
	 * @see org.springframework.security.core.Authentication#isAuthenticated()
	 */
	@Override
	public boolean isAuthenticated() {
		return this.isAuthenticated;
	}

	/**
	 * @see org.springframework.security.core.Authentication#setAuthenticated(boolean)
	 */
	@Override
	public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
		this.isAuthenticated = isAuthenticated;

	}
	
	/**
	 * Adds a JWT Header and cookie to the servlet response
	 * @param response the Response to be sent back
	 */
	public void addJwtToResponse(final HttpServletResponse response) {
	    final Claims authMap = Jwts.claims();
        this.getAuthorities().forEach(auth -> {
            authMap.put(auth.getAuthority(), auth.getAuthority());
        });
        // Finally capture user name
        authMap.put(SecurityConstants.USER_NAME_CLAIM,((User) this.getPrincipal()).getUsername());

        final String token = Jwts.builder()
                .setClaims(authMap).setExpiration(Config.PARAMS.getExpirationTime())
                .signWith(SignatureAlgorithm.HS512, Config.PARAMS.getSecret()).compact();

        // For standard web navigation
        Cookie jwtCookie = new Cookie(SecurityConstants.COOKIE_NAME, token);
        // FIXME: Uncomment next line for production
        // jwtCookie.setSecure(true);
        jwtCookie.setHttpOnly(true);
        response.addCookie(jwtCookie);
	}

}
