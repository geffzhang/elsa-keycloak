using Elsa.Studio.Contracts;
using Microsoft.AspNetCore.Components;

namespace ElsaStudioServer
{
    public class LoginPageProvider : IUnauthorizedComponentProvider
    {

        public RenderFragment GetUnauthorizedComponent()
        {
            return builder =>
            {
                builder.OpenComponent<RedirectToLogin>(0);
                builder.CloseComponent();
            };
        }
    }
}
