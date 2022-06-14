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
            Console.WriteLine($"FromForm: {grant_type}");
            string body = string.Empty;
            try
            {
                using (StreamReader stream = new StreamReader(Request.Body))
                {
                    body = stream.ReadToEndAsync().Result;
                }
            }
            catch (Exception ex) { }
            Console.WriteLine($"payload: {body}");
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

    }
}