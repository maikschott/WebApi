using System;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Masch.WebApi.Owin.Middleware.Authentication.Basic
{
  public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
  {
    protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
    {
      // 1) Basic auth should only be used as a last resort, in case there is no other authentication handler.
      // 2) If Options.AuthenticatorAsync is set it may use a database to look up users, which is expensive and doesn't be done anyway if we  already have an authentication.
      if (Context.Request.User?.Identity?.IsAuthenticated == true) { return null; }

      return await AuthenticateByUri().ConfigureAwait(false) ?? await AuthenticateByHttpHeader().ConfigureAwait(false);
    }

    protected override Task ApplyResponseChallengeAsync()
    {
      if (Response.StatusCode == (int)HttpStatusCode.Unauthorized &&
          Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode) != null)
      {
        Response.Headers.Append("WWW-Authenticate", new AuthenticationHeaderValue(Options.AuthenticationType, Options.Realm == null ? null : $"realm=\"{Options.Realm}\"").ToString());

        if (Options.UseUtf8)
        {
          Response.Headers.AppendValues("WWW-Authenticate", "charset=\"UTF-8\"");
        }
      }

      return Task.CompletedTask;
    }

    private Task<AuthenticationTicket> AuthenticateByUri()
    {
      if (Options.AllowUriUsername && !string.IsNullOrEmpty(Request.Uri.UserInfo))
      {
        var usernameAndPassword = Request.Uri.UserInfo.Split(new[] { ':' }, 2);
        return DoAuthenticateAsync(usernameAndPassword[0], usernameAndPassword.Length >= 2 ? usernameAndPassword[1] : null);
      }

      return Task.FromResult<AuthenticationTicket>(null);
    }

    private async Task<AuthenticationTicket> AuthenticateByHttpHeader()
    {
      foreach (var authorization in Request.Headers.GetValues("Authorization") ?? Array.Empty<string>())
      {
        if (AuthenticationHeaderValue.TryParse(authorization, out var authenticationHeaderValue) && authenticationHeaderValue.Scheme == Options.AuthenticationType)
        {
          var (username, password) = Decode(authenticationHeaderValue.Parameter);
          return await DoAuthenticateAsync(username, password).ConfigureAwait(false);
        }
      }

      return null;
    }

    private async Task<AuthenticationTicket> DoAuthenticateAsync(string username, string password)
    {
      if (string.IsNullOrEmpty(username)) { return null; }

      var claims = Options.AuthenticatorAsync != null ? await Options.AuthenticatorAsync(username, password, Request.CallCancelled).ConfigureAwait(false) : new[] { new Claim(ClaimsIdentity.DefaultNameClaimType, username) };

      if (claims == null) { return null; }

      var identity = new ClaimsIdentity(claims, Options.AuthenticationType);
      return new AuthenticationTicket(identity, null);
    }

    private static (string UserName, string Password) Decode(string authParameter)
    {
      try
      {
        var basicAuthInfo = Encoding.UTF8.GetString(Convert.FromBase64String(authParameter)).Split(':');
        return (basicAuthInfo.Length >= 1 ? basicAuthInfo[0] : null, basicAuthInfo.Length >= 2 ? basicAuthInfo[1] : null);
      }
      catch (ArgumentException) { return (null, null); }
      catch (FormatException) { return (null, null); }
    }
  }
}