using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Components;
using System.Net;

namespace ElsaStudioServer.Pages
{
    public class SignoutModel : PageModel
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<SignoutModel> logger;

        public SignoutModel(IConfiguration configuration, ILogger<SignoutModel> logger)
        {
            this.configuration = configuration;
            this.logger = logger;
        }
        public async Task<IActionResult> OnGet()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);

            var redirect_uri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}";
            var url = new Uri(configuration["Oidc:Authority"])
                .AppendPathSegments("/protocol/openid-connect/logout")
                .SetQueryParam("post_logout_redirect_uri", redirect_uri)
                .SetQueryParam("client_id", configuration["Oidc:ClientId"]);
            return Redirect(url.ToString());

        }
    }
}