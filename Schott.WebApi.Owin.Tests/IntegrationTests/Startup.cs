using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using Masch.WebApi.Owin.Middleware.Authentication.Basic;
using Masch.WebApi.Owin.Middleware.Authentication.Token;
using Owin;

namespace Masch.WebApi.Owin.Tests.IntegrationTests
{
  public abstract class StartupBase
  {
    public void Configuration(IAppBuilder appBuilder)
    {
      var config = new HttpConfiguration();

      config.Routes.MapHttpRoute("Default", "api/{controller}/{action}");

      AddAuthorizationMiddleware(appBuilder);

      appBuilder.UseWebApi(config);
    }

    protected abstract void AddAuthorizationMiddleware(IAppBuilder appBuilder);
  }

  public class StartupWithBasicInbuiltAuthorizer : StartupBase
  {
    protected override void AddAuthorizationMiddleware(IAppBuilder appBuilder)
    {
      appBuilder.Use<BasicAuthenticationMiddleware>(new BasicAuthenticationOptions("WebAPI", null));
    }
  }

  public class StartupWithBasicCustomAuthorizer : StartupBase
  {
    protected override void AddAuthorizationMiddleware(IAppBuilder appBuilder)
    {
      appBuilder.Use<BasicAuthenticationMiddleware>(new BasicAuthenticationOptions("WebAPI", Authorize));
    }

    private static Task<Claim[]> Authorize(string username, string password, CancellationToken cancellationToken)
    {
      Claim[] claims;

      if (username == "user" && password == "pass")
      {
        claims = new[]
        {
          new Claim(ClaimsIdentity.DefaultNameClaimType, username),
          new Claim(ClaimsIdentity.DefaultRoleClaimType, "users")
        };
      }
      else if (username == "guest")
      {
        claims = new[]
        {
          new Claim(ClaimsIdentity.DefaultNameClaimType, username),
          new Claim(ClaimsIdentity.DefaultRoleClaimType, "guests")
        };
      }
      else
      {
        claims = null;
      }

      return Task.FromResult(claims);
    }

    public class StartupWithPlainTokenCustomAuthorizer : StartupWithBasicCustomAuthorizer
    {
      protected override void AddAuthorizationMiddleware(IAppBuilder appBuilder)
      {
        appBuilder.Use<TokenAuthenticationMiddleware>(new TokenAuthenticationOptions(false));
        base.AddAuthorizationMiddleware(appBuilder);
      }
    }

    public class StartupWithSecureTokenCustomAuthorizer : StartupWithBasicCustomAuthorizer
    {
      protected override void AddAuthorizationMiddleware(IAppBuilder appBuilder)
      {
        appBuilder.Use<TokenAuthenticationMiddleware>(new TokenAuthenticationOptions(true));
        base.AddAuthorizationMiddleware(appBuilder);
      }
    }
  }
}