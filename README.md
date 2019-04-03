# OWIN middleware for Basic Authentication

Enables the Basic authentication schema [RFC 7617](https://tools.ietf.org/html/rfc7617) for OWIN.

The username and password may be provided either by:
* setting the `Authorization` HTTP header to `Basic Base64Encoding(username:password)`, or
* providing the username and password as part of the URI, e.g. `https://username:password@localhost:8000/api/action`.

**Important:**
As the Basic authentication scheme transmits the user name and password in plaintext its should only be used for connections where the HTTP headers are encrypted, e.g. HTTPS.

## Usage

In your OWIN startup class setup the middleware as follows:
    
    app.Use<BasicAuthAuthenticationMiddleware>(new BasicAuthAuthenticationOptions("WebAPI", null));

The first parameter is the `realm` which is only informational and describes the scope for which the authentication is used.

The second parameter is an authorization delegate which receives the provided username and password and returns the claims, e.g. name, role, that are valid for the user or `null` if the user should not be authenticated.
If this parameter is `null` any user is authenticated with the default name claim. 

The following shows an exemplary implementation of a custom authenticator method, authenticating a `guest` user name and password with the _guest_ role.

    private Task<Claim[]> Authenticate(string username, string password, CancellationToken cancellationToken = default(CancellationToken))
    {
        Claim[] claims = null;
        if (username == "guest" && password == "guest")
        {
          claims = new[]
          {
            new Claim(ClaimsIdentity.DefaultNameClaimType, username),
            new Claim(ClaimsIdentity.DefaultRoleClaimType, "guest")
          };
        }
        
        return Task.FromResult(claims);
    }

In order to restrict access to your controller or only one controller action only the [AuthorizeAttribute](https://msdn.microsoft.com/en-us/library/system.web.http.authorizeattribute(v=vs.118).aspx) needs to be set:

    [Authorize(Users="guest")]
    public IHttpActionResult Get()
    {
      // do something
    }

or

    [Authorize(Roles="guest")]
    public IHttpActionResult Get()
    {
      // do something
    }

For details see [Authentication and Authorization in ASP.NET Web API](https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/authentication-and-authorization-in-aspnet-web-api).

# OWIN middleware for cached authentication via tokens
The `TokenAuthenticationMiddleware` provides a caching mechanism for authentication.

Usually, the authenticator method described above would match a user against a database.
However, doing this for every request can be very costly. The `TokenAuthenticationMiddleware`,
checks if a user was authenticated and automatically sets a cookie with a JSON Web Token containing all the claims.
For each subsequent request the client would sent this cookie along, which would be intercepted by the
`TokenAuthenticationMiddleware` and authenticate the user with the stored claims.

The `BasicAuthentication` middleware will recognize that a user is already authenticated, skipping its own authentication
and thus not trigger the authenticator method.

## Usage

      app.Use<TokenAuthenticationMiddleware>(new TokenAuthenticationOptions(false));
      app.Use<BasicAuthenticationMiddleware>(new BasicAuthenticationOptions("WebAPI", Authenticate));

The `TokenAuthenticationMiddleware` must be placed first in order to process any request before the `BasicAuthenticationMiddleware`.
