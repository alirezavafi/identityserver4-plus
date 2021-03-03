using DataAccess.EFModels;
using IdentityServer4.Configuration;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SSO.Identity.Stores.EntityFramework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AutoWrapper;
using CoreLib.Services.Otp;

namespace SSO.Identity
{
    public class IdentityServerPlusOptions
    {
        public int SsoLifeTimeInMinutes { get; set; } = 120;
        public bool SsoIsSlidingExpiration { get; set; } = false;
        public Action<DbContextOptionsBuilder> DbContextConfiguration { get; set; }
        public string TokenSigningCertificatePath { get; set; }
        public string TokenSigningCertificationPassword { get; set; }
    }
    
    public static class IdentityStartup
    {
        public static IServiceCollection AddApplicationIdentity(this IServiceCollection services, IdentityServerPlusOptions opt, IHostEnvironment env)
        {
            services.AddDataProtection()
                    .SetApplicationName("Customers-SSO")
                    .PersistKeysToDbContext<IdentityServerDataProtectionDbContext>();

            services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
                {
                    options.Password.RequireDigit = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequiredLength = 6;
                    options.Password.RequiredUniqueChars = 1;
                    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(60);
                    options.Lockout.MaxFailedAccessAttempts = 5;
                    options.Lockout.AllowedForNewUsers = true;
                    options.User.AllowedUserNameCharacters =
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                    options.User.RequireUniqueEmail = false;
                    options.SignIn.RequireConfirmedAccount = true;
                    options.SignIn.RequireConfirmedPhoneNumber = true;
                })
                .AddDefaultTokenProviders();

            services.AddTransient<IRoleStore<ApplicationRole>, NullRoleStore>();
            services.AddTransient<ApplicationUserManager>();
            services.AddTransient<IProfileService, ProfileService>();
            services.AddTransient<IOtpService, OtpService>();
            services.AddIdentityStore<EfUserStore>();
            
            var migrationsAssembly = typeof(IdentityStartup).GetType().Assembly.GetName().Name;
            var builder = services.AddIdentityServer(
                    options =>
                    {
                        options.Events.RaiseErrorEvents = true;
                        options.Events.RaiseInformationEvents = true;
                        options.Events.RaiseFailureEvents = true;
                        options.Events.RaiseSuccessEvents = true;
                        options.UserInteraction.LoginUrl = "/ui/login";
                        options.UserInteraction.LogoutUrl = "/ui/logout";
                        options.UserInteraction.ErrorUrl = "/ui/error";
                        options.Authentication = new AuthenticationOptions()
                        {
                            CookieLifetime = TimeSpan.FromMinutes(opt.SsoLifeTimeInMinutes),
                            CookieSlidingExpiration = opt.SsoIsSlidingExpiration,
                            CookieAuthenticationScheme = Constants.DefaultAuthenticationSchemeName
                        };
                        options.Caching.ClientStoreExpiration = TimeSpan.FromDays(7);
                        options.Caching.ResourceStoreExpiration = TimeSpan.FromDays(7);
                        options.Caching.CorsExpiration = TimeSpan.FromDays(7);
                    })
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = opt.DbContextConfiguration;
                    options.DefaultSchema = "Configuration";
                })
                .AddConfigurationStoreCache()
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = opt.DbContextConfiguration;
                    options.EnableTokenCleanup = true;
                    options.DefaultSchema = "Operation";
                })
                .AddAspNetIdentity<ApplicationUser>()
                .AddCorsPolicyService<DefaultCorsPolicyService>()
                //.AddCorsPolicyService<CorsPolicyService>()
                //.AddCorsPolicyCache<CorsPolicyService>()
                .AddProfileService<ProfileService>();

            if (env.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                var signCertPath = Path.Combine(env.ContentRootPath, opt.TokenSigningCertificatePath);
                Console.WriteLine("Setting sign cert:" + signCertPath);
                var rsaCertificate = new X509Certificate2(signCertPath, opt.TokenSigningCertificationPassword);
                builder.AddSigningCredential(rsaCertificate);
            }

            services.AddAuthentication(Constants.DefaultAuthenticationSchemeName)
                .AddCookie(Constants.DefaultAuthenticationSchemeName)
                .AddCookie(Constants.PartialAuthenticationSchemeName);

            services.AddSingleton<ICorsPolicyService>((container) =>
            {
                var logger = container.GetRequiredService<ILogger<DefaultCorsPolicyService>>();
                return new DefaultCorsPolicyService(logger)
                {
                    AllowAll = true,
                    //AllowedOrigins = { "http://localhost:4200", "https://exchange-code.ebidar-preview.com", "https://exchange-code-api.ebidar-preview.com", "https://exchange-code.ebidar.com" }
                };
            });

            services.AddRazorPages();
            return services;
        }

        public static void AddIdentityStore<T>(this IServiceCollection services) where T : class, IApplicationUserStore
        {
            services.AddTransient<IUserStore<ApplicationUser>, T>();
            services.AddTransient<IApplicationUserStore, T>();
            services.AddTransient<IUserPasswordStore<ApplicationUser>, T>();
            services.AddTransient<IUserSecurityStampStore<ApplicationUser>, T>();
            services.AddTransient<IUserLockoutStore<ApplicationUser>, T>();
            services.AddTransient<IUserEmailStore<ApplicationUser>, T>();
        }

        public static void UseApplicationIdentityServer(this IApplicationBuilder app)
        {
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
            
            using (var scope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();
                scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.Migrate();
                scope.ServiceProvider.GetRequiredService<ApplicationIdentityDbContext>().Database.Migrate();
            }
            app.UseIdentityServer();
        }

    }
}
