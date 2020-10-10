using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace Masch.WebApi.Owin.Middleware.Authentication.Token
{
  public class TokenAuthenticationMiddleware : AuthenticationMiddleware<TokenAuthenticationOptions>
  {
    public TokenAuthenticationMiddleware(OwinMiddleware next, TokenAuthenticationOptions options)
      : base(next, options)
    {
    }

    protected override AuthenticationHandler<TokenAuthenticationOptions> CreateHandler()
    {
      return new TokenAuthenticationHandler();
    }
  }
}