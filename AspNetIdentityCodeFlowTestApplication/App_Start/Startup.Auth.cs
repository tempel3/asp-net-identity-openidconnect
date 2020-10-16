using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Autofac;
using Autofac.Integration.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace AspNetIdentityCodeFlowTestApplication
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            
            // TODO different location
            var builder = new ContainerBuilder();

            // STANDARD MVC SETUP:

            // Register your MVC controllers.
            builder.RegisterControllers(typeof(MvcApplication).Assembly);

            // Run other optional steps, like registering model binders,
            // web abstractions, etc., then set the dependency resolver
            // to be Autofac.
            

            var applicationUserManager = new ApplicationUserManager(new MyUserStorage());
            
            builder.RegisterType<ApplicationUserManager>().AsSelf().InstancePerRequest();
            builder.RegisterType<ApplicationSignInManager>().AsSelf().InstancePerRequest();
            builder.Register<IUserStore<ApplicationUser>>(c => new MyUserStorage()).InstancePerRequest();;
            builder.Register(c => HttpContext.Current.GetOwinContext().Authentication).As<IAuthenticationManager>();
            builder.Register<IdentityFactoryOptions<ApplicationUserManager>>(c =>
                new IdentityFactoryOptions<ApplicationUserManager>()
                {
                    DataProtectionProvider = new DpapiDataProtectionProvider()
                });
            
            var container = builder.Build();
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
            
            // Configure the db context, user manager and signin manager to use a single instance per request
            // app.CreatePerOwinContext(ApplicationDbContext.Create);
            // app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            // app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);
            
            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            
            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
            
            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // TODO helps?
            //https://coding.abel.nu/2014/11/catching-the-system-webowin-cookie-monster/
            app.UseKentorOwinCookieSaver();
            
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions()
            {

                Authority = "#",
                ClientId = "#",
                ClientSecret = "#",
                
                RedirectUri = "https://localhost:44378/",
                PostLogoutRedirectUri = "https://localhost:44378/",
                               

                Scope = "openid profile email",
                // https://www.microsoftpressstore.com/articles/article.aspx?p=2473126&seqNum=2
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                // SignInAsAuthenticationType = "Cookies", // ApplicationCookie

                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    MessageReceived = async (c) => {
                        var code = c.ProtocolMessage.Code;
                        Console.WriteLine(code);

                        // TODO state?
                        //POST {tokenEndpoint} Content-Type: application/x-www-form-urlencoded   grant_type=authorization_code& code=41e120f9-701f-49ec-8fa7-206d5166f1b2.a4064c5b-bc21-4900-8508-cc9f219ae615.94095913-942f-45d3-9a62-ffa9494452a1& client_id=pdf-analyzer-spa& client_secret={clientSecret}& redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug
                        //https://oidcdebugger.com/debug

                        await Task.CompletedTask;
                    },
                    SecurityTokenReceived = async (c) => {
                        await Task.CompletedTask;
                    },
                    RedirectToIdentityProvider = async (c) => {
                        await Task.CompletedTask;
                    },
                    SecurityTokenValidated = async (c) => {
                        await Task.CompletedTask;
                    },
                    AuthorizationCodeReceived = async (context) =>
                    {
                        var code = context.Code;
                        string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

                        
                        // var appAuthManager = DependencyResolver.Current.GetService<IApplicationAuthenticationManager>();
                        var userManager = DependencyResolver.Current.GetService<ApplicationUserManager>();
                        var userManager2 = DependencyResolver.Current.GetService<UserManager<ApplicationUser>>();
                        var signInManager = DependencyResolver.Current.GetService<ApplicationSignInManager>();

                        var email = context.AuthenticationTicket.Identity.FindFirst("preferred_username");

                        var user = userManager.FindByName(email.Value);
                        if (user == null)
                        {
                            return;
                        }


                        await signInManager.SignInAsync(user, false, false);
                            
                        await Task.CompletedTask;

                    },
                    AuthenticationFailed = (context) =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/Error?message=" + context.Exception.Message);
                        return Task.FromResult(0);
                    }
                }

                //TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters() { 
            });

            // Register the Autofac middleware FIRST, then the Autofac MVC middleware.
            app.UseAutofacMiddleware(container);
            app.UseAutofacMvc();
        }
    }
    
    
    
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
            
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context) 
        {
            var manager = new ApplicationUserManager(new MyUserStorage());
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = 
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configure the application sign-in manager which is used in this application.
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
    
    
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser: IUser<string> // : IdentityUser
    {
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
                // Add custom user claims here
            return userIdentity;
        }

        public string Id { get; set; }
        public string UserName { get; set; }
    }


    public class MyUserStorage : IUserStore<ApplicationUser>
    {
        private List<ApplicationUser> users = new List<ApplicationUser>();


        public MyUserStorage()
        {
            users.Add(new ApplicationUser()
            {
                Id = "test",
                UserName = "test"
            });
        }
        
        public void Dispose()
        {
            users = null;
        }

        public Task CreateAsync(ApplicationUser user)
        {
            users.Add(user);
            return Task.CompletedTask;
        }

        public Task UpdateAsync(ApplicationUser user)
        {
            // notwendig?
            var existingUser = users.FirstOrDefault(i=>i.Id == user.Id);
            users.Remove(existingUser);
            users.Add(user);
            
            return Task.CompletedTask;
        }

        public Task DeleteAsync(ApplicationUser user)
        {
            var existingUser = users.FirstOrDefault(i=>i.Id == user.Id);
            users.Remove(existingUser);
            return Task.CompletedTask;
        }

        public Task<ApplicationUser> FindByIdAsync(string userId)
        {
            var existingUser = users.FirstOrDefault(i=>i.Id == userId);
            return Task.FromResult(existingUser);
        }

        public Task<ApplicationUser> FindByNameAsync(string userName)
        {
            var existingUser = users.FirstOrDefault(i=>i.UserName == userName);
            return Task.FromResult(existingUser);
        }
    }
    
}