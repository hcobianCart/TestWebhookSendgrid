using Google.Cloud.Functions.Framework;
using Google.Cloud.Functions.Hosting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

namespace TokenServiceCF
{
    public class Function : IHttpFunction
    {
        private readonly IConfiguration Configuration;
        public Function(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }
        public async Task HandleAsync(HttpContext context)
        {
            try
            {
                context.Response.ContentType = "application/json";
                string grant_type = String.Empty;
                if (context.Request.Method == "POST" && context.Request.Body != null)
                {
                    ContentType contentType = new ContentType(context?.Request.ContentType);

                    switch (contentType.MediaType)
                    {
                        case "application/x-www-form-urlencoded":
                            {
                                if (!context.Request.Form.IsNullOrEmpty() && context.Request.Form.TryGetValue("grant_type", out StringValues value))
                                {
                                    grant_type = value;
                                    var prefix = "Basic";
                                    var basicAuth = context?.Request?.Headers["Authorization"];
                                    if (basicAuth.HasValue && basicAuth.Value.Any() && basicAuth.Value[0].StartsWith(prefix))
                                    {
                                        var Inputcredentials = basicAuth.Value[0].Substring(prefix.Length).Trim();
                                        var Credentials = Base64Encode($"{Environment.GetEnvironmentVariable("client_id")}:{Environment.GetEnvironmentVariable("client_secret")}");
                                        if (!Credentials.Equals(Inputcredentials))
                                        {
                                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                                            await context.Response.WriteAsync(string.Empty);
                                            return;
                                        }
                                        else
                                        {
                                            if (!grant_type.Equals("client_credentials"))
                                            {
                                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                                await context.Response.WriteAsync("unsupported_grant_type");
                                                return;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                                        await context.Response.WriteAsync(string.Empty);
                                        return;
                                    }
                                    var token = GenerateJWT(Environment.GetEnvironmentVariable("SB_JWT_CLIENT_KEY"), Configuration["SB_Jwt_Client:Issuer"], Configuration["SB_Jwt_Client:Audience"]);
                                    context.Response.StatusCode = StatusCodes.Status200OK;
                                    await JsonSerializer.SerializeAsync(context.Response.Body, new { access_token = token, token_type = "Bearer" });
                                    return;
                                }
                                else
                                {
                                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                    await context.Response.WriteAsync("unsupported_grant_type");
                                    return;
                                }
                                break;
                            }
                    }
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    await context.Response.WriteAsync(string.Empty);
                    return;
                }
            }
            catch (Exception ex) {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync(String.Empty);
                return;
            }
        }
        private static string GenerateJWT(string key, string issuer, string audience)
        {
            var token = new JwtSecurityToken
                (
                issuer: issuer,
                audience: audience,
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }
    }
}
