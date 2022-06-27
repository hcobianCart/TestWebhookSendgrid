using Google.Cloud.Functions.Framework;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using EllipticCurve;
using Snowflake.Data.Client;
using System.Data;
using System.Text.Json;

namespace Cart.WebhookSendgridCF
{
    public class Function : IHttpFunction
    {
        private const string DEFAULT_ISSUER = "SB_Jwt_Client:Issuer";
        private const string DEFAULT_AUDIENCE = "SB_Jwt_Client:Audience";
        private const string DEFAULT_KEY = "SB_JWT_CLIENT_KEY";
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
                if (JwtMessageReceivedHandler(context, Configuration))
                {
                    string publicKey = Environment.GetEnvironmentVariable("SNOWFLAKE_PUBLICKEY");
                    string body = string.Empty;
                    using (StreamReader stream = new StreamReader(context.Request.Body))
                    {
                        body = await stream.ReadToEndAsync();
                    }
                    
                    if (VerifySignature(ConvertPublicKeyToECDSA(publicKey), body, context.Request.Headers[SIGNATURE_HEADER], context.Request.Headers[TIMESTAMP_HEADER]))
                    {
                        body = JavaScriptEscape(body);
                        var json = JsonDocument.Parse(body).RootElement;
                        var result = StoreInSnowflake(json);
                        await JsonSerializer.SerializeAsync(context.Response.Body, new { message = result });
                        if (result == "OK")
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                        }
                        else
                        {
                            context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        }
                        return;
                    }
                    else
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync(string.Empty);
                        return;
                    }
                    
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync(string.Empty);
                    return;
                }
            }
            catch (Exception ex) 
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync(ex.Message);
                return;
            }
        }
        private string ConnectionString()
        {
            var account = Environment.GetEnvironmentVariable("SNOWFLAKE_ACCOUNT");
            var user = Environment.GetEnvironmentVariable("SNOWFLAKE_USER");
            var passwd = Environment.GetEnvironmentVariable("SNOWFLAKE_PASSWORD");
            var db = Environment.GetEnvironmentVariable("SNOWFLAKE_DB");
            var schema = Environment.GetEnvironmentVariable("SNOWFLAKE_SCHEMA");
            var warehouse = Environment.GetEnvironmentVariable("SNOWFLAKE_WAREHOUSE");
            var role = Environment.GetEnvironmentVariable("SNOWFLAKE_ROLE");
            return $"account={account};user={user};password={passwd};db={db};schema={schema};warehouse={warehouse};role={role}";
        }
        private string Table()
        {
            var db = Environment.GetEnvironmentVariable("SNOWFLAKE_DB");
            var schema = Environment.GetEnvironmentVariable("SNOWFLAKE_SCHEMA");
            var table = Environment.GetEnvironmentVariable("SNOWFLAKE_TABLE");
            return $"{db}.{schema}.{table}";
        }
        private string StoreInSnowflake(JsonElement body)
        {
            using (IDbConnection conn = new SnowflakeDbConnection())
            {
                conn.ConnectionString = ConnectionString();
                conn.Open();

                if (body.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in body.EnumerateArray())
                    {
                        IDbCommand cmd = conn.CreateCommand();
                        var uuid = Guid.NewGuid();

                        cmd.CommandText = $"insert into {Table()} (UUID, BODY) (select :p0, to_variant(parse_json(:p1)))";
                        var pUUID = cmd.CreateParameter();
                        pUUID.ParameterName = "p0";
                        pUUID.DbType = System.Data.DbType.Guid;
                        pUUID.Value = uuid;
                        cmd.Parameters.Add(pUUID);

                        var pBODY = cmd.CreateParameter();
                        pBODY.ParameterName = "p1";
                        pBODY.DbType = System.Data.DbType.String;
                        pBODY.Value = item;
                        cmd.Parameters.Add(pBODY);

                        try
                        {
                            cmd.ExecuteNonQuery();
                        }
                        catch (Exception ex)
                        {
                            return ex.Message;
                        }
                    }
                }

                if (body.ValueKind == JsonValueKind.Object)
                {
                    IDbCommand cmd = conn.CreateCommand();
                    var uuid = Guid.NewGuid();

                    //TODO use parameterized queries
                    cmd.CommandText = $"insert into {Table()} (UUID, BODY) (select :p0, to_variant(parse_json(:p1)))";
                    var pUUID = cmd.CreateParameter();
                    pUUID.ParameterName = "p0";
                    pUUID.DbType = System.Data.DbType.Guid;
                    pUUID.Value = uuid;
                    cmd.Parameters.Add(pUUID);

                    var pBODY = cmd.CreateParameter();
                    pBODY.ParameterName = "p1";
                    pBODY.DbType = System.Data.DbType.String;
                    pBODY.Value = body;
                    cmd.Parameters.Add(pBODY);
                    try
                    {
                        cmd.ExecuteNonQuery();
                    }
                    catch (Exception ex)
                    {
                        return ex.Message;
                    }
                }
                conn.Close();
            }
            return "OK";
        }
        /// <summary>
        /// Signature verification HTTP header name for the signature being sent.
        /// </summary>
        public const string SIGNATURE_HEADER = "X-Twilio-Email-Event-Webhook-Signature";

        /// <summary>
        /// Timestamp HTTP header name for timestamp.
        /// </summary>
        public const string TIMESTAMP_HEADER = "X-Twilio-Email-Event-Webhook-Timestamp";

        /// <summary>
        /// Convert the public key string to a <see cref="PublicKey"/>.
        /// </summary>
        /// <param name="publicKey">verification key under Mail Settings</param>
        /// <returns>public key using the ECDSA algorithm</returns>
        private EllipticCurve.PublicKey ConvertPublicKeyToECDSA(string publicKey)
        {
            return EllipticCurve.PublicKey.fromPem(publicKey);
        }

        /// <summary>
        /// Verify signed event webhook requests.
        /// </summary>
        /// <param name="publicKey">elliptic curve public key</param>
        /// <param name="payload">event payload in the request body</param>
        /// <param name="signature">value obtained from the 'X-Twilio-Email-Event-Webhook-Signature' header</param>
        /// <param name="timestamp">value obtained from the 'X-Twilio-Email-Event-Webhook-Timestamp' header</param>
        /// <returns>true or false if signature is valid</returns>
        private bool VerifySignature(EllipticCurve.PublicKey publicKey, string payload, string signature, string timestamp)
        {
            var timestampedPayload = timestamp + payload;
            var decodedSignature = Signature.fromBase64(signature);
            return Ecdsa.verify(timestampedPayload, decodedSignature, publicKey);
        }
        private string JavaScriptEscape(string text)
        {
            return text
                .Replace(@"\u005c", "\\")
                .Replace(@"\u0022", "\"")
                .Replace(@"\u0027", "'")
                .Replace(@"\u0026", "&")
                .Replace(@"\u003c", "<")
                .Replace(@"\u003e", ">");
        }
        private static bool JwtMessageReceivedHandler(HttpContext context, IConfiguration Configuration)
        {
            var prefix = "Bearer";
            var token = context?.Request?.Headers["Authorization"];
            if (token.HasValue && token.Value.Any() && token.Value[0].StartsWith(prefix))
            {
                var bearerToken = token.Value[0].Substring(prefix.Length).Trim();
                var jwtHandler = new JwtSecurityTokenHandler();

                if (bearerToken == null || bearerToken.Length == 0)
                    return false;

                JwtSecurityToken jwt;
                try
                {
                    jwt = (JwtSecurityToken)jwtHandler.ReadToken(bearerToken);
                }
                catch (Exception ex)
                {
                    return false;
                }

                var audiences = jwt?.Audiences;

                if (audiences == null)
                    return false;

                if (audiences.Count() == 0)
                    return false;

                var audience = audiences.FirstOrDefault();

                if (context == null)
                {
                    return false;
                }

                if (!string.IsNullOrEmpty(audience) && audience == Configuration[DEFAULT_AUDIENCE])
                {
                    TokenValidationParameters validationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = false,
                        ValidIssuers = new[] { Configuration[DEFAULT_ISSUER] },
                        ValidAudiences = new[] { Configuration[DEFAULT_AUDIENCE] },
                        IssuerSigningKeys = new[] { (SecurityKey)(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable(DEFAULT_KEY)))) }
                    };
                    SecurityToken validatedToken;
                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    var user = handler.ValidateToken(bearerToken, validationParameters, out validatedToken);
                    var aud = user.Claims?.Where(c => c.Type == "aud");
                    if (aud == null || !aud.Any())
                        return false;
                    var claim = aud.FirstOrDefault();
                    if (!string.IsNullOrEmpty(claim.Value) && claim.Value == Configuration[DEFAULT_AUDIENCE])
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            return false;
        }
    }
}
