using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace WebApi.Owin.Middleware.Authentication.Token
{
  internal class TokenAuthenticationHandler : AuthenticationHandler<TokenAuthenticationOptions>
  {
    protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
    {
      var jwtCookie = Request.Cookies.FirstOrDefault(x => x.Key == "JWT").Value;
      if (jwtCookie != null)
      {
        Request.Headers.Append("Authorization", new AuthenticationHeaderValue(Options.AuthenticationType, jwtCookie).ToString());
      }

      var authorizations = Request.Headers.GetValues("Authorization") ?? Array.Empty<string>();
      foreach (var authorization in authorizations)
      {
        if (AuthenticationHeaderValue.TryParse(authorization, out var authenticationHeaderValue) && authenticationHeaderValue.Scheme == Options.AuthenticationType)
        {
          var token = JsonWebToken.Create(authenticationHeaderValue.Parameter, Options.Key);
          if (token != null)
          {
            var claims = ConvertJwtClaimsToClrClaims(token.Payload);
            if (claims != null)
            {
              var identity = new ClaimsIdentity(claims, Options.AuthenticationType, "sub", ClaimsIdentity.DefaultRoleClaimType);
              return Task.FromResult(new AuthenticationTicket(identity, null));
            }
          }
        }
      }

      return Task.FromResult<AuthenticationTicket>(null);
    }

    protected override Task ApplyResponseChallengeAsync()
    {
      if (Request.User?.Identity?.IsAuthenticated == true && Request.User.Identity.AuthenticationType != Options.AuthenticationType)
      {
        var token = new JsonWebToken
        {
          SignatureAlgorithm = Options.SignatureAlgorithm,
          Secret = Options.Key,
          Payload = ConvertClrClaimsToJwtClaims(Context.Authentication.User.Claims)
        };
        Response.Cookies.Append("JWT", token.Serialize(), new CookieOptions { HttpOnly = true/*, Secure = Options.Secure*/ });
        //response.Append("WWW-Authenticate", new AuthenticationHeaderValue(Options.AuthenticationType, CreateToken(basicAuthTicket.Identity.Claims)).ToString());
      }

      return Task.CompletedTask;
    }

    private static IDictionary<string, object> ConvertClrClaimsToJwtClaims(IEnumerable<Claim> claims)
    {
      var result = new Dictionary<string, object>
      {
        ["iat"] = DateTime.Now,
        ["jti"] = Guid.NewGuid().ToString()
      };

      foreach (var claim in claims)
      {
        object value;
        switch (claim.ValueType)
        {
          case ClaimValueTypes.Boolean:
            value = bool.Parse(claim.Value);
            break;
          case ClaimValueTypes.Integer:
          case ClaimValueTypes.Integer32:
          case ClaimValueTypes.Integer64:
            value = long.Parse(claim.Value, CultureInfo.InvariantCulture);
            break;
          case ClaimValueTypes.Double:
            value = double.Parse(claim.Value, CultureInfo.InvariantCulture);
            break;
          case ClaimValueTypes.Date:
          case ClaimValueTypes.DateTime:
            value = DateTime.Parse(claim.Value, CultureInfo.InvariantCulture);
            break;
          default:
            value = claim.Value;
            break;
        }

        result[claim.Type == ClaimsIdentity.DefaultNameClaimType ? "sub" : claim.Type] = value;
      }

      return result;
    }

    private static IEnumerable<Claim> ConvertJwtClaimsToClrClaims(IDictionary<string, object> jwtClaims)
    {
      foreach (var claim in jwtClaims)
      {
        yield return new Claim(claim.Key, (claim.Value as IFormattable)?.ToString(null, CultureInfo.InvariantCulture) ?? claim.Value?.ToString());
      }
    }
  }
}