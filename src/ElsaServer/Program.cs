using Elsa.Extensions;
using FastEndpoints.Swagger;
using Keycloak.AuthServices.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

using Elsa.EntityFrameworkCore.Modules.Management;
using Elsa.EntityFrameworkCore.Modules.Runtime;
using Elsa.EntityFrameworkCore.Extensions;

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
                elsa.UseWorkflowManagement(management => management.UseEntityFrameworkCore(ef => ef.UseSqlite()));

                elsa.UseWorkflowRuntime(runtime =>
                {
                    runtime.UseEntityFrameworkCore(ef => ef.UseSqlite());
                });
                elsa.UseJavaScript();
                elsa.UseLiquid(); 
                //elsa.UseWorkflowRuntime(runtime => runtime.AddWorkflow<HelloWorldHttpWorkflow>());
                elsa.UseHttp();
                elsa.UseWorkflowsApi();
            });

            builder.Services.AddKeycloakAuthentication(builder.Configuration, options =>
            {
                options.RequireHttpsMetadata = false;
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        //var appContext = context.Request.HttpContext.RequestServices.GetService<AppContext>();
                        //appContext.OnTokenValidated(context);
                        ////todo: add code to check
                        return Task.CompletedTask;
                    }
                };
            });

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