using EllipticCurve;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Snowflake.Data.Client;
using System.Data;
using System.Text.Json;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestWebhookSendgrid : ControllerBase
    {
        [HttpPost]
        [Authorize]
        public async Task<string> SaveMetrics()
        {
            try
            {
                string publicKey = Environment.GetEnvironmentVariable("SNOWFLAKE_PUBLICKEY");
                string body = string.Empty;
                using (StreamReader stream = new StreamReader(Request.Body))
                {
                    body = await stream.ReadToEndAsync();
                }
                if (VerifySignature(ConvertPublicKeyToECDSA(publicKey), body, Request.Headers[SIGNATURE_HEADER], Request.Headers[TIMESTAMP_HEADER]))
                {
                    Console.WriteLine($"payload: {body}");
                    body = JavaScriptEscape(body);
                    var json = JsonDocument.Parse(body).RootElement;
                    StoreInSnowflake(json);
                }
            }
            catch (Exception ex) { }

            return "ok";
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
        private void StoreInSnowflake(JsonElement body)
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

                        //TODO use parameterized queries
                        cmd.CommandText = $"insert into {Table()} (UUID, BODY) (select '{uuid}', to_variant(parse_json('{item}')))";
                        try
                        {
                            cmd.ExecuteNonQuery();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Array item: {item.ToString()}");
                            Console.WriteLine(ex.ToString());
                            //TODO Handle bad unicode
                        }
                    }
                }

                if (body.ValueKind == JsonValueKind.Object)
                {
                    IDbCommand cmd = conn.CreateCommand();
                    var uuid = Guid.NewGuid();

                    //TODO use parameterized queries
                    cmd.CommandText = $"insert into {Table()} (UUID, BODY) (select '{uuid}', to_variant(parse_json('{body}')))";
                    try
                    {
                        cmd.ExecuteNonQuery();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Object: {body.ToString()}");
                        Console.WriteLine(ex.ToString());
                        //Handle bad unicode
                    }
                }

                conn.Close();
            }
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
        private PublicKey ConvertPublicKeyToECDSA(string publicKey)
        {
            return PublicKey.fromPem(publicKey);
        }

        /// <summary>
        /// Verify signed event webhook requests.
        /// </summary>
        /// <param name="publicKey">elliptic curve public key</param>
        /// <param name="payload">event payload in the request body</param>
        /// <param name="signature">value obtained from the 'X-Twilio-Email-Event-Webhook-Signature' header</param>
        /// <param name="timestamp">value obtained from the 'X-Twilio-Email-Event-Webhook-Timestamp' header</param>
        /// <returns>true or false if signature is valid</returns>
        private bool VerifySignature(PublicKey publicKey, string payload, string signature, string timestamp)
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

    }
}