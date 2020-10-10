using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Owin.Testing;
using Xunit;

namespace Masch.WebApi.Owin.Tests.IntegrationTests.Basic
{
  public enum AuthorizeType
  {
    Uri, // cannot be tested as the the OWIN test server omits URI user information
    Header
  };

  public abstract class BasicAuthenticationTestBase<TStartup> : IDisposable
    where TStartup : StartupBase
  {
    protected const string UserCredentials = "user:pass";
    protected const string GuestCredentials = "guest";

    protected readonly TestServer server;

    protected BasicAuthenticationTestBase()
    {
      server = TestServer.Create<TStartup>();
    }

    void IDisposable.Dispose()
    {
      server.Dispose();
    }

    [Fact]
    public void NoAuthorizationShouldFail()
    {
      var response = server.HttpClient.GetAsync("/api/test/any").Result;

      Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    //[InlineData(AuthorizeType.Uri, "any")]
    //[InlineData(AuthorizeType.Uri, "concreteuser")]
    [InlineData(AuthorizeType.Header, "any")]
    [InlineData(AuthorizeType.Header, "concreteuser")]
    public void ValidUser_ShouldAuthorize(AuthorizeType type, string action)
    {
      var response = Authorize(type, action, UserCredentials);

      Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    protected HttpResponseMessage Authorize(AuthorizeType type, string action, string credentials)
    {
      return type == AuthorizeType.Uri ? UriAuthorize(action, credentials) : HeaderAuthorize(action, credentials);
    }

    protected HttpResponseMessage UriAuthorize(string action, string credentials)
    {
      return server
        .CreateRequest($"{server.BaseAddress.Scheme}://{UserCredentials}@{server.BaseAddress.Host}/api/test/{action}")
        .GetAsync().Result;
    }

    protected HttpResponseMessage HeaderAuthorize(string action, string credentials)
    {
      return server
        .CreateRequest($"/api/test/{action}")
        .AddHeader("Authorization", new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials))).ToString())
        .GetAsync().Result;
    }
  }
}