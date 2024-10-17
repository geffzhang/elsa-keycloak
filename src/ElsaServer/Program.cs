using Elsa.EntityFrameworkCore.Extensions;
using Elsa.EntityFrameworkCore.Modules.Management;
using Elsa.EntityFrameworkCore.Modules.Runtime;
using Elsa.Extensions;
using FastEndpoints.Swagger;
using Keycloak.AuthServices.Authentication;
using Keycloak.AuthServices.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace ElsaServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configure CORS to allow designer app hosted on a different origin to invoke the APIs.
            builder.Services.AddCors(cors => cors
                .AddDefaultPolicy(policy => policy
                    .AllowAnyOrigin() // For demo purposes only. Use a specific origin instead.
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .WithExposedHeaders("x-elsa-workflow-instance-id"))); // Required for Elsa Studio in order to support running workflows from the designer. Alternatively, you can use the `*` wildcard to expose all headers.

            // Add services to the container.
            Elsa.EndpointSecurityOptions.DisableSecurity();

            builder.Services.AddControllers();
            builder.Services.AddElsa(elsa =>
            {
                elsa.UseWorkflowManagement(management => 
                        management.UseEntityFrameworkCore(ef => 
                               ef.UsePostgreSql(builder.Configuration.GetConnectionString("elsadb")!))
                        );
                elsa.UseWorkflowRuntime(runtime =>
                {
                    runtime.UseEntityFrameworkCore(ef =>
                               ef.UsePostgreSql(builder.Configuration.GetConnectionString("elsadb")!));
                });
                elsa.UseJavaScript();
                elsa.UseLiquid();
                elsa.UseHttp();
                elsa.UseWorkflowsApi();
 

                // Use timers.
                elsa.UseQuartz();
                elsa.UseScheduling(scheduling => scheduling.UseQuartzScheduler());

            });

            var keycloakSection = builder.Configuration.GetSection("Keycloak");
            builder.Services.AddOptions<KeycloakAuthenticationOptions>("keycloak");

            KeycloakAuthenticationOptions keycloakOptions = new();
            keycloakSection.Bind(keycloakOptions, opt => opt.BindNonPublicProperties = true);
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(opts =>
                {
                    const string roleClaimType = "role";
                    var validationParameters = new TokenValidationParameters
                    {
                        ClockSkew = keycloakOptions.TokenClockSkew,
                        ValidateAudience = keycloakOptions.VerifyTokenAudience ?? true,
                        ValidateIssuer = false,
                        NameClaimType = "preferred_username",
                        RoleClaimType = roleClaimType,
                    };

            var sslRequired = string.IsNullOrWhiteSpace(keycloakOptions.SslRequired)
                || keycloakOptions.SslRequired
                    .Equals("external", StringComparison.OrdinalIgnoreCase);

            opts.Authority = keycloakOptions.KeycloakUrlRealm;
            opts.Audience = keycloakOptions.Resource;
            opts.TokenValidationParameters = validationParameters;
            opts.RequireHttpsMetadata = sslRequired;
            opts.SaveToken = true;
        });
            KeycloakAuthorizationOptions options = new();
            keycloakSection.Bind(options, opt => opt.BindNonPublicProperties = true);
            // Authorization
            builder.Services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                       .RequireAuthenticatedUser()
                       .Build();

            })
            .AddKeycloakAuthorization()
            .AddAuthorizationServer(builder.Configuration);


            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            //builder.Services.AddEndpointsApiExplorer();
            //builder.Services.AddSwaggerGen();
            builder.Services.SwaggerDocument(); //define a swagger document

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {

                //Microsoft.AspNetCore.Builder.SwaggerBuilderExtensions.UseSwagger(app);
                //app.UseSwaggerUI();
            }

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.UseWorkflows();
            app.UseWorkflowsApi();
            app.UseSwaggerGen(); //add this
            app.Run();
        }
    }
}