using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Masch.WebApi.Owin.Middleware.Authentication.Basic
{
  /// <summary>
  /// OWIN middleware to enable authentication via the "Basic" authentication scheme.<para/>
  /// The "Basic" authentication scheme transmits the user name and password in plaintext and thus should only be used for
  /// connections where the HTTP headers are encrypted, e.g. HTTPS.
  /// </summary>
  /// <example>
  /// Register the middleware to the OWIN <see cref="IAppBuilder"/> <c>app</c>.
  /// <code>app.Use&lt;BasicAuthAuthenticationMiddleware&gt;(new BasicAuthAuthenticationOptions("WebAPI", null));</code>
  ///
  /// This example uses the simplified authentication process, where any user is authenticated.
  ///
  /// In order to authenticate a user based on their credentials, provide an <see cref="AuthenticatorDelegate"/> method for the second options parameter.
  /// </example>
  public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
  {
    public BasicAuthenticationMiddleware(OwinMiddleware next, BasicAuthenticationOptions options)
      : base(next, options)
    {
    }

    protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
    {
      return new BasicAuthenticationHandler();
    }
  }
}