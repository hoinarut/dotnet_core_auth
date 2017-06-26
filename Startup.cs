using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TokenAuth.Auth;

namespace TokenAuth
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }
        private TokenProviderOptions tokenOptions;
        private TokenValidationParameters tokenValidationParams;
        private SymmetricSecurityKey securityKey;
        private static readonly string secretKey = "mysecretkey_supersecret";

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
            tokenOptions = new TokenProviderOptions
            {
                Audience = "ExampleAudience",
                Issuer = "ExampleIssuer",
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256),
            };

            services.AddSingleton<TokenProviderOptions>(tokenOptions);
            services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser().Build());
            });

            // Add framework services.
            services.AddMvc();
        }


        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            tokenValidationParams = new TokenValidationParameters
            {
                IssuerSigningKey = securityKey,
                ValidAudience = tokenOptions.Audience,
                ValidIssuer = tokenOptions.Issuer,
                ValidateLifetime = true,
                ClockSkew = tokenOptions.Expiration
            };
            app.UseJwtBearerAuthentication(new JwtBearerOptions
            {
                TokenValidationParameters = tokenValidationParams,
                AutomaticAuthenticate = true,
                AutomaticChallenge = true
            });

            app.UseStaticFiles();

            // Add JWT generation endpoint:
            app.UseMiddleware<TokenProviderMiddleware>(Options.Create(tokenOptions));

            app.UseMvc();
        }
    }
}
