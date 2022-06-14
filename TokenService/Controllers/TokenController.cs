using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace TokenService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration Configuration;
        public TokenController(IConfiguration configuration)
        {
            this.Configuration = configuration; 
        }

        [HttpPost(Name = "Token")]
        public IActionResult Post([FromForm] string grant_type)
        {
            Console.WriteLine($"grant_type : {grant_type}");
            Console.WriteLine($"grant_type : {Request?.Headers["Authorization"]}");
            var prefix = "Basic";
            var basicAuth = Request?.Headers["Authorization"];
            if (basicAuth.HasValue && basicAuth.Value.Any() && basicAuth.Value[0].StartsWith(prefix))
            {
                var Inputcredentials = basicAuth.Value[0].Substring(prefix.Length).Trim();
                var Credentials = Base64Encode($"{Environment.GetEnvironmentVariable("client_id")}:{Environment.GetEnvironmentVariable("client_secret")}");
                if (!Credentials.Equals(Inputcredentials))
                {
                    return Unauthorized();
                }
                else
                {
                    if (!grant_type.Equals("client_credentials"))
                    {
                        return Unauthorized("unsupported_grant_type");
                    }
                }
            }
            else
            {
                return Unauthorized();
            }
            var token = GenerateJWT(Environment.GetEnvironmentVariable("SB_JWT_CLIENT_KEY"), Configuration["SB_Jwt_Client:Issuer"], Configuration["SB_Jwt_Client:Audience"]);
            return Ok(new { access_token = token, token_type  = "Bearer" });
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

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

    }
}