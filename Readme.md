# Salesforce Canvas and Spring Boot

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

### The challenge
Salesforce canvas offers a capable integration point between Salesforce and external applications to surface them inside the Salesforce UI. One of the aspects is establishing identiy. There are two options: OAuth and a signed request. I'm looking at the later. A signed request posts (as in HTTP POST) a digitally signed JSON request to the external application.

When all you need is a single page, validating the request and returning the result is all that needs to be done. It becomes trickier when you want to navigate in the application and when that application runs in the cloud with multiple load balanced instances, so you might end up on a different instance mid-flight.

### The approach
Build a [Spring Boot](https://projects.spring.io/spring-boot/) application that provides an authentication endpoint suitable for a Canvas POST and other endpoints that only allow authenticated access. The security will be provided by [Json Web Tokens](https://jwt.io/) a.k.a JWT or [RFC 7519](https://tools.ietf.org/html/rfc7519).

As added challenge: The application will require standard link and form based navigation, so we can't rely on AJAX to provide additional "stuff" into the requests from/to the server. And yes - needs to be able to run on [Heroku](https://www.heroku.com/) on multiple instances (Dynos in Heroku language) without the sticky session feature switched on.

### Environment variables to be set

- `JWT_SECRET` - the token used to encrypt the JWT. Ideally randomized on each restart, but needs to be the same in a dyno 
- `SFDC_SECRET` - The client token shared with the Canvas definition in Salesforce

(and a few others - discover for yourself)

### Application endpoints

- `/` The homepage - access unauthenticated
- `/login` - admin login
- `/hw` - Hello world page. Throws a 403 if not authenticated
- `/sfdcauth/[target]` target URL for canvas integration. Post your signed request here. Replace `[target]` with the endpoint you want to reach e.g. `/sfdcauth/hw` to reach `/hw` after authentication

### Resources

No man is an island, and without [the tubes](https://en.wikipedia.org/wiki/Series_of_tubes) we are lost. Here is what I used:

- [Heroku](https://www.heroku.com/)
- [GitHub](https://github.com/stwissel/) - get the sample project there
- [Spring Boot](https://projects.spring.io/spring-boot/)
- [Spring Initializr](https://start.spring.io/) - even with the `@EnableWebMvc` causing initial grief
- [Spring Boot and Mustache](http://www.baeldung.com/spring-boot-mustache) - I'm a big fan of [Mustache](http://mustache.github.io/) since it works everywhere
- [Auth0 on Spring and JWT](https://auth0.com/blog/implementing-jwt-authentication-on-spring-boot/) - the blog post that showed the moving pieces
- [Stackoverflow](https://stackoverflow.com/users/131021/stwissel) (how do you code?)