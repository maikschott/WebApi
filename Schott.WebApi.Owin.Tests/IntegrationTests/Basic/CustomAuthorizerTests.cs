using System.Net;
using Xunit;

namespace Masch.WebApi.Owin.Tests.IntegrationTests.Basic
{
  public class CustomAuthorizerTests : BasicAuthenticationTestBase<StartupWithBasicCustomAuthorizer>
  {
    [Theory]
    //[InlineData(AuthorizeType.Uri)]
    [InlineData(AuthorizeType.Header)]
    public void CorrectRole_ShouldAuthorize(AuthorizeType type)
    {
      var result = Authorize(type, "concreterole", UserCredentials);

      Assert.Equal(HttpStatusCode.NoContent, result.StatusCode);
    }

    [Theory]
    //[InlineData(AuthorizeType.Uri)]
    [InlineData(AuthorizeType.Header)]
    public void IncorrectRole_ShouldNotAuthorize(AuthorizeType type)
    {
      var result = Authorize(type, "concreterole", GuestCredentials);

      Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
    }

    [Theory]
    //[InlineData(AuthorizeType.Uri, "any")]
    //[InlineData(AuthorizeType.Uri, "concreteuser")]
    //[InlineData(AuthorizeType.Uri, "concreterole")]
    [InlineData(AuthorizeType.Header, "any")]
    [InlineData(AuthorizeType.Header, "concreteuser")]
    [InlineData(AuthorizeType.Header, "concreterole")]
    public void InvalidUser_ShouldNotAuthorize(AuthorizeType type, string action)
    {
      var result = Authorize(type, action, "invalid_credentials");

      Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
    }
  }
}