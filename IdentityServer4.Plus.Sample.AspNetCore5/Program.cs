using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Compact;
using Serilog.Sinks.SystemConsole.Themes;

namespace IdentityServer4.Plus.Sample.AspNetCore5
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilogPlus(ConfigureLogger)
                .ConfigureWebHostDefaults(webBuilder => { webBuilder.UseStartup<Startup>(); });

        private static void ConfigureLogger(LoggerConfiguration config)
        {
            config
                //.MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Verbose)
                .WriteTo.Console(
                    LogEventLevel.Information, 
                    theme: SystemConsoleTheme.Colored, 
                    outputTemplate:  "[{Timestamp:HH:mm:ss} {Level:u3}] {Message}{NewLine}{Properties}{NewLine}{Exception}{NewLine}"
                    );
        }
    }
}