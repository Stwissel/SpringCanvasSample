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

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        http
                /* Allow the app to show in a frame */
                .headers().frameOptions().disable()
                .and()
                /* always create a server session */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
                /*
                 * Define the URLs that can be accesses without authentication
                 */
                .authorizeRequests()
                .antMatchers("/",
                        "/favicon.ico",
                        "/404.html",
                        "/403.html",
                        "/500.html",
                        "/sfdcauth/**",
                        "/login",
                        "/logout",
                        "/password",
                        "/images/**",
                        "/css/**",
                        "/fonts/**",
                        "/icons/**")
                .permitAll()
                /* Require all others to be authenticated */
                .anyRequest().authenticated()
                .and()
                /* Add the filter that turns JWT into authentication */
                .addFilter(new CanvasAuthorizationFilter(this.authenticationManager()))
                /*
                 * allow direct access to the POST form for Canvas use without a
                 * _csrd token
                 */
                .csrf()
                .ignoringAntMatchers("/sfdcauth/**");
    }
}
