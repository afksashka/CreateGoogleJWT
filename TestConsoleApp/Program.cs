using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Text;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using JWT.Builder;
using System.Net.Http.Headers;

namespace TestConsoleApp
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            const string privateKeyPem = "private_key_here";
            var header = new { alg = "RS256", typ = "JWT", kid = "private_key_id_here" };
            var headerJson = JsonConvert.SerializeObject(header);
            var encodedHeader = Base64UrlEncoder.Encode(headerJson);

            var payload = new
            {
                iss = "client_email_here",
                sub = "client_email_here",
                aud = "https://fleetengine.googleapis.com/",
                iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                exp = DateTimeOffset.UtcNow.AddMinutes(60).ToUnixTimeSeconds(),
                authorization = new
                {
                    vehicleid = "*",
                    tripid = "*"
                }
            };
            var payloadJson = JsonConvert.SerializeObject(payload);
            var encodedPayload = Base64UrlEncoder.Encode(payloadJson);

            var jwt = $"{encodedHeader}.{encodedPayload}";
            var reader = new StringReader(privateKeyPem);

            var pemReader = new PemReader(reader);
            var privateKey = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
            var rsaKey = DotNetUtilities.ToRSA(privateKey);
            var securityKey = new RsaSecurityKey(rsaKey);
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
            var token = new JwtSecurityToken(jwt, signingCredentials: creds);
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(token);
            Console.WriteLine(encodedJwt);

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", encodedJwt);
            var response = await client.GetAsync("https://fleetengine.googleapis.com/v1/providers/<PROJECT_ID_HERE>/vehicles");
            var responseStr = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseStr);

        }

    }
}

