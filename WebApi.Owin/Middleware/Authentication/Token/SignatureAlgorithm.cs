using System.Diagnostics.CodeAnalysis;

namespace Masch.WebApi.Owin.Middleware.Authentication.Token
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum SignatureAlgorithm
  {
    None,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512
  }
}