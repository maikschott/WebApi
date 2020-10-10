using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Masch.WebApi.Owin.Middleware.Authentication.Basic
{
  public delegate Task<Claim[]> AuthenticatorDelegate(string username, string password, CancellationToken cancellationToken = default(CancellationToken));

  public class BasicAuthenticationOptions : AuthenticationOptions
  {
    /// <summary>
    ///   Sets the Basic authentication options.
    /// </summary>
    /// <param name="realm">[optional] Realm (will be shown by a browser when asking for credentials)</param>
    /// <param name="authenticatorAsync">
    ///   Provides the claims (usually <see cref="ClaimTypes.Name" /> and <see cref="ClaimTypes.Role" />) for a user name and
    ///   password.
    ///   <para />
    ///   If <see langword="null" /> the password is ignored and user is automatically authenticated by setting the
    ///   <see cref="ClaimTypes.Name" /> claim.
    /// </param>
    public BasicAuthenticationOptions(string realm, AuthenticatorDelegate authenticatorAsync)
      : base("Basic")
    {
      Realm = realm;
      AuthenticatorAsync = authenticatorAsync;
    }

    public string Realm { get; set; }

    public bool AllowUriUsername { get; set; } = true;

    /// <summary>
    ///   The WWW-Authenticate challenge will include the <c>charset="UTF-8"</c> value parameter according to
    ///   <a href="https://tools.ietf.org/html/rfc7617">RFC 7617</a>.
    ///   This is done in order to notify the client that the user name and password will be treated as UTF-8.
    ///   <para />
    ///   Set to <see langword="false" /> for compatibility with the obsolete
    ///   <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>, which doesn't define this header value parameter.
    /// </summary>
    public bool UseUtf8 { get; set; } = true;

    public AuthenticatorDelegate AuthenticatorAsync { get; }
  }
}