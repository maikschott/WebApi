using System.Web.Http;

namespace Masch.WebApi.Owin.Tests.IntegrationTests
{
  public class TestController : ApiController
  {
    [HttpGet]
    [Authorize]
    public void Any()
    {
    }

    [HttpGet]
    [Authorize(Users = "user")]
    public void ConcreteUser()
    {
    }

    [HttpGet]
    [Authorize(Roles = "users")]
    public void ConcreteRole()
    {
    }
  }
}