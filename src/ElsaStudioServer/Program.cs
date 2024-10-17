using Blazored.LocalStorage;
using Elsa.Studio.Contracts;
using Elsa.Studio.Core.BlazorServer.Extensions;
using Elsa.Studio.Dashboard.Extensions;
using Elsa.Studio.Extensions;
using Elsa.Studio.Login.BlazorServer.Services;
using Elsa.Studio.Login.Contracts;
using Elsa.Studio.Login.HttpMessageHandlers;
using Elsa.Studio.Login.Services;
using Elsa.Studio.Models;
using Elsa.Studio.Shell.Extensions;
using Elsa.Studio.Webhooks.Extensions;
using Elsa.Studio.WorkflowContexts.Extensions;
using Elsa.Studio.Workflows.Designer.Extensions;
using Elsa.Studio.Workflows.Extensions;
using ElsaStudioServer;

// Build the host.
var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// Register Razor services.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor(options =>
{
    // Register the root components.
    options.RootComponents.RegisterCustomElsaStudioElements();
});
// Register shell services and modules.
builder.Services.AddCore();
builder.Services.AddShell(options => configuration.GetSection("Shell").Bind(options));
builder.Services.AddKeycloak(builder.Configuration.GetSection("Oidc"));
builder.Services.AddDataProtection();

var backendApiConfig = new BackendApiConfig
{
    ConfigureBackendOptions = options => configuration.GetSection("Backend").Bind(options),
    ConfigureHttpClientBuilder = options => options.AuthenticationHandler = typeof(AuthenticatingApiHttpMessageHandler),
};

builder.Services.AddRemoteBackend(backendApiConfig);
builder.Services.AddTransient<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddScoped<IUnauthorizedComponentProvider, ElsaStudioServer.LoginPageProvider>();
builder.Services.AddScoped<IJwtAccessor, BlazorServerJwtAccessor>();
// Register HttpContextAccessor.
builder.Services.AddHttpContextAccessor();

// Register Blazored LocalStorage.
builder.Services.AddBlazoredLocalStorage();

// Register JWT services.
builder.Services.AddSingleton<IJwtParser, BlazorServerJwtParser>();


builder.Services.AddScoped<ICredentialsValidator, DefaultCredentialsValidator>();
builder.Services.AddDashboardModule();
builder.Services.AddWorkflowsModule();
builder.Services.AddWorkflowContextsModule();
builder.Services.AddWebhooksModule();

// Configure SignalR.
builder.Services.AddSignalR(options =>
{
    // Set MaximumReceiveMessageSize:
    options.MaximumReceiveMessageSize = 5 * 1024 * 1000; // 5MB
});


// Build the application.
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseResponseCompression();
    
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

// Run the application.
app.Run();