using System;
using Microsoft.Owin.Security;

namespace Schott.WebApi.Owin.Middleware.Authentication.Token
{
  public class TokenAuthenticationOptions : AuthenticationOptions
  {
    public TokenAuthenticationOptions(bool secure)
      : base("Bearer")
    {
      if (secure)
      {
        SignatureAlgorithm = SignatureAlgorithm.HMACSHA256;
        Key = Guid.NewGuid().ToByteArray();
      }
    }

    public SignatureAlgorithm SignatureAlgorithm { get; set; }

    public byte[] Key { get; set; }
  }
}