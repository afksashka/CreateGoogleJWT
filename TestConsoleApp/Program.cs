using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;

namespace TestConsoleApp
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            /*
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
            */

            var privateKeyPem = "private_key_here";

            // Check if privateKey is Pkcs or RSA
            bool isPkcsPrivateKey = privateKeyPem.Contains("BEGIN PRIVATE KEY");

            if (isPkcsPrivateKey)
                privateKeyPem = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty);
            else
                privateKeyPem = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty).Replace("-----END RSA PRIVATE KEY-----", string.Empty);

            privateKeyPem = privateKeyPem
                .Replace(Environment.NewLine, string.Empty)
                .Replace("\n", string.Empty);

            var privateKey = Convert.FromBase64String(privateKeyPem);

            using RSA rsa = RSA.Create();

            if (isPkcsPrivateKey)
                rsa.ImportPkcs8PrivateKey(privateKey, out _);
            else
                rsa.ImportRSAPrivateKey(privateKey, out _);

            var securityKey = new RsaSecurityKey(rsa);
            //securityKey.KeyId = "private_key_id_here"; // Add it with jwt.Header

            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            var claims = new List<Claim> {
                new Claim("iss", "client_email_here"),
                new Claim("sub", "client_email_here"),
                new Claim("aud", "https://fleetengine.googleapis.com/"),
                new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim("exp", DateTimeOffset.UtcNow.AddMinutes(60).ToUnixTimeSeconds().ToString()),
                new Claim("authorization", JsonConvert.SerializeObject(
                    new {
                        deliveryvehicleid = "*",
                        trackingid = "*",
                        taskid = "*",
                        vehicleid = "*",
                        tripid = "*"
                    }))
            };

            var jwt = new JwtSecurityToken(
                claims: claims,
                signingCredentials: signingCredentials
            );

            jwt.Header.Add("kid", "private_key_id_here");

            // Generate JWT token
            string token = new JwtSecurityTokenHandler().WriteToken(jwt);

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var projectId = "<PROJECT_ID_HERE>";

            // Get vehicles
            Console.WriteLine("Get vehicles");
            var url = $"https://fleetengine.googleapis.com/v1/providers/{projectId}/vehicles";
            var response = await client.GetAsync(url);
            var responseStr = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseStr);

            // Create vehicle
            Console.WriteLine("Create vehicle");
            var createvehicleDto = new
            {
                vehicleState = "OFFLINE",
                supportedTripTypes = new[] { "EXCLUSIVE" },
                maximumCapacity = 4,
                vehicleType = new { category = "AUTO" },
                attributes = new[] { new { key = "on_trip", value = "false" } }
            };
            url = $"https://fleetengine.googleapis.com/v1/providers/{projectId}/vehicles?vehicleId=vid-1";
            var data = new StringContent(JsonConvert.SerializeObject(createvehicleDto), Encoding.UTF8, "application/json");
            response = await client.PostAsync(url, data);
            responseStr = await response.Content.ReadAsStringAsync();
            Console.WriteLine(responseStr);

            Console.WriteLine("Finish");
            Console.ReadLine();
        }
    }
}
