using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(AspNetIdentityCodeFlowTestApplication.Startup))]
namespace AspNetIdentityCodeFlowTestApplication
{
  public partial class Startup
  {
    public void Configuration(IAppBuilder app)
    {
      ConfigureAuth(app);
    }
  }
}