
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TestWebhookSendgrid.Auth
{
    //TODO For Brand Console we will be using CartID and Auth0 for
    //authenticating the endpoints.  This authentication mechanism will only be
    //used by store front.

    //TODO We might be able to use an organizational service accounts for the
    //management portion of the service too.  At that point this code can be
    //removed

    /* 
     * 
     * This is a slight rewrite of the authentication method used in the
     * shipping service.  It basically works the same way though by using two
     * different secrets to identify "Manager" and "Client" calls.
     * 
     *  - "Manager" bearer token is needed for calls to the registration
     *  services
     *
     *  - "Client" bearer tokens can be used for customer facing endpoints such
     *  as sending email, sms, etc.
     *  
     *  Both types use a jwt bearer Authorization and the correct key is used
     *  for validating the signature based on the audience.
     *  
     *  For the manager calls we might want to use something more secure such
     *  as a set of key-pairs were we know the public keys of the source
     *  systems or we will need to setup service accounts and the login will
     *  need to happen from   For the clients we might want to generate a
     *  unique token for each registration.
     *
     */


    public enum AuthPolicy{
        Client,
        Manager
    }

    public static class AuthHelper
    {
        private const string DEFAULT_ISSUER = "SB_Jwt_Client:Issuer";
        private const string DEFAULT_AUDIENCE = "SB_Jwt_Client:Audience";
        private const string DEFAULT_KEY = "SB_JWT_CLIENT_KEY";


        public static TokenValidationParameters JwtDefaultValidationParameters(WebApplicationBuilder builder)
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, //TODO: Review this later when user authentication is added
                ValidIssuers = new[] { builder.Configuration[DEFAULT_ISSUER]},
                ValidAudiences = new[] { builder.Configuration[DEFAULT_AUDIENCE] },
                IssuerSigningKeys = new[] { (SecurityKey)(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration[DEFAULT_KEY]))) },
            };            
        }

        public static Task JwtMessageReceivedHandler(WebApplicationBuilder builder, MessageReceivedContext context)
       {
            var prefix = "Bearer";
            var token = context?.HttpContext?.Request?.Headers["Authorization"];
            if (token.HasValue && token.Value.Any() && token.Value[0].StartsWith(prefix))
            {
                var bearerToken = token.Value[0].Substring(prefix.Length).Trim();
                var jwtHandler = new JwtSecurityTokenHandler();

                if (bearerToken == null || bearerToken.Length == 0)
                    return Task.CompletedTask;

                JwtSecurityToken jwt;
                try
                {
                    jwt = (JwtSecurityToken)jwtHandler.ReadToken(bearerToken);
                }
                catch (Exception ex)
                {
                    return Task.FromException(ex);
                }
                
                var audiences = jwt?.Audiences;

                if (audiences == null)
                    return Task.CompletedTask;

                if (audiences.Count() == 0)
                    return Task.CompletedTask;

                var audience = audiences.FirstOrDefault();

                if (context == null)
                {
                    return Task.CompletedTask;
                }
                
                //TODO if we allow each client to have a separate auth token we will need to validate the issuer and pull the correct key from the secret store
                if (!string.IsNullOrEmpty(audience) && audience == builder.Configuration["SB_Jwt_Client:Audience"])
                {
                    context.Options.TokenValidationParameters.ValidIssuer = builder.Configuration["SB_Jwt_Client:Issuer"];
                    context.Options.TokenValidationParameters.ValidAudience = builder.Configuration["SB_Jwt_Client:Audience"];
                    context.Options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["SB_JWT_CLIENT_KEY"]));
                }
            }

            return Task.CompletedTask;
        }
        public static Task JwtTokenValidationHandler(WebApplicationBuilder builder, TokenValidatedContext context)
        {
            //TODO do we want to return without setting the new Principal?
            //
            //Seems like it would be ok since none of the endpoints would validate
            //correctly.  We should always have an audience since the token is valid
            //at this point.
            var aud = context?.Principal?.Claims?.Where(c => c.Type == "aud");
            if (aud == null || !aud.Any())
                return Task.CompletedTask;

            var claim = aud.FirstOrDefault();
            
            //TODO do we want to append the Principal instead of overwriting the current one?
            if (!string.IsNullOrEmpty(claim.Value) && claim.Value == builder.Configuration["SB_Jwt_Client:Audience"])
            {
                var claims = new List<Claim> { new Claim("Type", "Client", ClaimValueTypes.String) };
                var userIdentity = new ClaimsIdentity(claims, AuthPolicy.Client.ToString());
                context.Principal = new ClaimsPrincipal(userIdentity);
            }
            else
            {
                var claims = new List<Claim> { new Claim("Type", "Manager", ClaimValueTypes.String) };
                var userIdentity = new ClaimsIdentity(claims, AuthPolicy.Manager.ToString());
                context.Principal = new ClaimsPrincipal(userIdentity);
            }

            return Task.CompletedTask;
        }

        public static bool IsUserRole(this IHttpContextAccessor accessor, AuthPolicy policy)
        {
            var identity = accessor?.HttpContext?.User?.Identity;

            if (identity == null) return false;
            
            return (identity.IsAuthenticated && identity.AuthenticationType == policy.ToString());
        }
    }
}
