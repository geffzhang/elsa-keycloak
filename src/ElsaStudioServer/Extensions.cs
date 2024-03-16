using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Elsa.Studio.Contracts;

namespace ElsaStudioServer
{
    public static class Extensions
    {
        public static AuthenticationBuilder AddKeycloak(this IServiceCollection services, IConfigurationSection config)
        {
            var oidcOptions = new OpenIdConnectOptions();
            config.Bind(oidcOptions);
            services.AddSingleton(oidcOptions);

            var builder = services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie(option =>
                {
                })
                //.AddCookie(options =>
                //{
                //    options.Cookie.SameSite = SameSiteMode.None;
                //    options.Cookie.Name = "AuthCookie";
                //    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                //    options.SlidingExpiration = true;
                //    options.Events = new CookieAuthenticationEvents
                //    {
                //        OnValidatePrincipal = async c =>
                //        {
                //            // this event is fired everytime the cookie has been validated by the cookie middleware, so basically during every authenticated request.
                //            // the decryption of the cookie has already happened so we have access to the identity + user claims
                //            // and cookie properties - expiration, etc..
                //            // source: https://github.com/mderriey/aspnet-core-token-renewal/blob/2fd9abcc2abe92df2b6c4374ad3f2ce585b6f953/src/MvcClient/Startup.cs#L57
                //            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                //            var expires = c.Properties.ExpiresUtc.GetValueOrDefault().ToUnixTimeSeconds();

                //            if (now >= expires)
                //            {
                //                var response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                //                {
                //                    Address = oidcOptions.Authority +
                //                              "/protocol/openid-connect/token",
                //                    ClientId = oidcOptions.ClientId,
                //                    ClientSecret = oidcOptions.ClientSecret,
                //                    RefreshToken =
                //                        ((ClaimsIdentity)c.Principal.Identity)
                //                        .GetClaimValue(ClaimType
                //                            .RefreshToken)
                //                }).ConfigureAwait(false);

                //                if (!response.IsError)
                //                {
                //                    ((ClaimsIdentity)c.Principal.Identity)
                //                        .SetIdentityClaims(response.AccessToken, response.RefreshToken);

                //                    c.ShouldRenew = true;
                //                }
                //            }
                //        }
                //    };
                //})
                .AddOpenIdConnect(options =>
                {
                    options.Authority = oidcOptions.Authority;
                    //options.AuthenticationMethod = OpenIdConnectRedirectBehavior.FormPost;
                    options.ClientId = oidcOptions.ClientId;
                    options.ClientSecret = oidcOptions.ClientSecret;
                    options.SaveTokens = true;
                    options.ResponseType = oidcOptions.ResponseType;
                    options.Resource = oidcOptions.Resource;
                    options.RequireHttpsMetadata = oidcOptions.RequireHttpsMetadata; // dev only
                    options.GetClaimsFromUserInfoEndpoint =oidcOptions.GetClaimsFromUserInfoEndpoint; // does not work together with options.resource
                    options.SaveTokens = oidcOptions.SaveTokens;
                    //must set to unspecified
                    options.NonceCookie.SameSite = SameSiteMode.Unspecified;
                    options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;

                    options.Scope.Clear();
                    foreach (var scope in oidcOptions.Scope) options.Scope.Add(scope);

                    options.Events = new OpenIdConnectEvents
                    {
                        OnTokenResponseReceived = async(t) =>
                        {
                            //store token
                        },

                        OnTokenValidated = (t) =>
                        {
                            // this event is called after the OIDC middleware received the authorization code,
                            // redeemed it for an access token + a refresh token and validated the identity token
                            ((ClaimsIdentity)t.Principal.Identity)
                                .SetIdentityClaims(t.TokenEndpointResponse.AccessToken,
                                    t.TokenEndpointResponse.RefreshToken);

                            t.Properties.ExpiresUtc =
                                new JwtSecurityToken(t.TokenEndpointResponse.AccessToken)
                                    .ValidTo; // align expiration of the cookie with expiration of the access token
                            t.Properties.IsPersistent =
                                true; // so that we don't issue a session cookie but one with a fixed expiration

                            return Task.CompletedTask;
                        }
                    };
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "groups",
                        ValidateIssuer = true
                    };
                    
                });
            return builder;
        }

        /// <summary>
        /// Gets an identity claim
        /// </summary>
        /// <returns></returns>
        public static Claim GetClaim(this ClaimsIdentity source, string type)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return default;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                return claim;
            }

            return default;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static string GetClaimValue(this ClaimsIdentity source, string type)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return default;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                return claim.Value;
            }

            return default;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity SetClaim(this ClaimsIdentity source, Claim claim)
        {
            if (source == null || claim == null)
            {
                return source;
            }

            if (source.FindFirst(claim.Type) != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(claim);
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity SetClaimValue(this ClaimsIdentity source, string type, string value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value));
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value.ToString()));
            return source;
        }

        /// <summary>
        /// Adds or updates a identity claim
        /// </summary>
        /// <returns></returns>
        public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long? value)
        {
            if (source == null || string.IsNullOrEmpty(type))
            {
                return source;
            }

            var claim = source.FindFirst(type);
            if (claim != null)
            {
                source.RemoveClaim(claim);
            }

            source.AddClaim(new Claim(type, value?.ToString()));
            return source;
        }

        public static ClaimsIdentity SetIdentityClaims(this ClaimsIdentity source, string accessToken, string refreshToken)
        {
            return source
                .SetClaimValue(ClaimType.AccessToken, accessToken)
                .SetClaimValue(ClaimType.RefreshToken, refreshToken)
                .SetClaimValue(ClaimType.AccessTokenExpires, ((DateTimeOffset)new JwtSecurityToken(accessToken).ValidTo).ToUnixTimeSeconds().ToString())
                .SetClaimValue(ClaimType.RefreshTokenExpires, ((DateTimeOffset)new JwtSecurityToken(refreshToken).ValidTo).ToUnixTimeSeconds().ToString());
        }
    }
}
