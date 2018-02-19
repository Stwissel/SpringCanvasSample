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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.notessensei.heroku.springcanvassample.security.Config;

/**
 *
 * The unavoidable HelloWorld example
 * 
 * @author swissel
 *
 */
@Controller
public class HelloWorld {

    private List<String> adminList = new ArrayList<>(Arrays.asList("/metrics",
            "/loggers",
            "/auditevents",
            "/beans",
            "/heapdump",
            "/health",
            "/env",
            "/autoconfig",
            "/mappings",
            "/trace",
            "/dump",
            "/info",
            "/loggers"
            ));

    @RequestMapping(value = "/hw", method = RequestMethod.GET)
    public String index(Model model, Principal principal) {
        model.addAttribute("id", UUID.randomUUID().toString());
        String usr = principal.getName();
        model.addAttribute("username", usr);
        if (usr.equals(Config.PARAMS.getAdminUserName())) {
            model.addAttribute("adminList", adminList);
        } else {
            model.addAttribute("adminList",new ArrayList<>());
        }
        // return the template to use
        return "helloworld";
    }
}
