using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ApnsConnectionExperiment
{
    class Program
    {
        private static CryptoProviderFactory _cryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false };

        static int Main(string[] args)
        {
            MainAsync(args).GetAwaiter().GetResult();
            return 0;
        }

        static async Task MainAsync(string[] args)
        {
            var pooledConnectionLifetime = TimeSpan.FromSeconds(10);
            var maxConnectionsPerServer = 10000;
            var degreeOfParallelism = 50;
            var testDuration = TimeSpan.FromMinutes(1);
            var endpoint = "https://api.sandbox.push.apple.com/3/device/";
            if (args.Length > 0)
            {
                pooledConnectionLifetime = TimeSpan.Parse(args[0]);
                maxConnectionsPerServer = int.Parse(args[1]);
                degreeOfParallelism = int.Parse(args[2]);
                testDuration = TimeSpan.Parse(args[3]);
                endpoint = args[4];
            }

            var socketHttpHandler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = pooledConnectionLifetime,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12,
                },
                MaxConnectionsPerServer = maxConnectionsPerServer
            };

            var url = $"{endpoint}{Guid.NewGuid():N}";

            var appleCredentials = new AppleCredentials
            {
                AppId = Credentials.AppId,
                AppName = Credentials.AppName,
                KeyId = Credentials.KeyId,
                Token = Credentials.Token,
            };

            var now = DateTimeOffset.UtcNow;
            AppleJwtToken appleJwtToken = null;
            var jwtTokenPath = $"{Directory.GetCurrentDirectory()}\\jwtToken.txt";
            if (File.Exists(jwtTokenPath))
            {
                appleJwtToken = JsonConvert.DeserializeObject<AppleJwtToken>(File.ReadAllText(jwtTokenPath));
            }
            if (appleJwtToken == null || !appleJwtToken.IsValid(DateTimeOffset.UtcNow.Add(testDuration).Add(TimeSpan.FromMinutes(1))))
            {
                appleJwtToken = GenerateJwtToken(appleCredentials, now, now.AddHours(1));
                File.WriteAllText(jwtTokenPath, JsonConvert.SerializeObject(appleJwtToken));
            }

            using (var httpClient = new HttpClient(socketHttpHandler, true))
            {
                await Task.WhenAll(Enumerable.Range(0, degreeOfParallelism).Select(async (x) =>
                {
                    while (DateTime.UtcNow < now.Add(testDuration))
                    {
                        await Send(httpClient, url, appleCredentials.AppId, appleJwtToken);
                    }
                }));
            }
        }

        private static async Task Send(HttpClient httpClient, string url, string appId, AppleJwtToken appleJwtToken)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Headers.Add("apns-id", Guid.NewGuid().ToString("D"));
                request.Headers.Add("apns-push-type", "alert");
                request.Headers.Add("apns-priority", "10");
                request.Headers.Add("apns-topic", appId);
                request.Headers.Add("authorization", BuildAuthorizationHeader(appleJwtToken.Token));

                var payload = new JObject{
                        {
                            "aps", new JObject
                            {
                                { "alert", $"Test alert {DateTimeOffset.UtcNow}" },
                                { "content-available", 1 }
                            }
                        }
                    };

                request.Content = new StringContent(payload.ToString());
                request.Version = new Version(2, 0);
                try
                {
                    var timer = Stopwatch.StartNew();
                    using (var httpResponseMessage = await httpClient.SendAsync(request))
                    {
                        Console.WriteLine($"{timer.ElapsedMilliseconds},{httpResponseMessage.StatusCode}");
                        var responseContent = await httpResponseMessage.Content.ReadAsStringAsync();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    throw;
                }
            }
        }

        private static string BuildAuthorizationHeader(string providerToken) => $"bearer {providerToken}";

        private static AppleJwtToken GenerateJwtToken(AppleCredentials appleCredentials, DateTimeOffset issuedAt, DateTimeOffset expires)
        {
            if (appleCredentials is null)
            {
                throw new ArgumentNullException(nameof(appleCredentials));
            }
            if (string.IsNullOrWhiteSpace(appleCredentials.AppId))
            {
                throw new ArgumentException("AppId cannot be null", nameof(appleCredentials.AppId));
            }
            if (string.IsNullOrWhiteSpace(appleCredentials.AppName))
            {
                throw new ArgumentException("AppName cannot be null", nameof(appleCredentials.AppName));
            }
            if (string.IsNullOrWhiteSpace(appleCredentials.KeyId))
            {
                throw new ArgumentException("KeyId cannot be null", nameof(appleCredentials.KeyId));
            }
            if (string.IsNullOrWhiteSpace(appleCredentials.Token))
            {
                throw new ArgumentException("Token cannot be null", nameof(appleCredentials.Token));
            }

            CngKey cngKey;
            try
            {
                cngKey = CngKey.Import(Convert.FromBase64String(appleCredentials.Token!), CngKeyBlobFormat.Pkcs8PrivateBlob);
            }
            catch (Exception)
            {
                throw new FormatException("APNS credential token is not valid. Should be a valid BASE64 string and should not include -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- strings.");
            }

            using (cngKey)
            {
                using (var ecdca = new ECDsaCng(cngKey))
                {
                    var encryptingKey = new ECDsaSecurityKey(ecdca) { KeyId = appleCredentials.KeyId };

                    var signingCredentials = new SigningCredentials(encryptingKey, SecurityAlgorithms.EcdsaSha256) { CryptoProviderFactory = _cryptoProviderFactory };

                    var securityTokenDescriptor = new SecurityTokenDescriptor
                    {
                        SigningCredentials = signingCredentials,
                        Issuer = appleCredentials.AppId,
                        IssuedAt = issuedAt.UtcDateTime,
                        Expires = expires.UtcDateTime
                    };

                    var tokenHandler = new JwtSecurityTokenHandler
                    {
                        SetDefaultTimesOnTokenCreation = false
                    };
                    var unsignedToken = tokenHandler.CreateJwtSecurityToken(securityTokenDescriptor);
                    unsignedToken.Header["kid"] = appleCredentials.KeyId;
                    var encodedToken = tokenHandler.WriteToken(unsignedToken);

                    var appleJwtToken = new AppleJwtToken
                    {
                        Token = encodedToken,
                        ValidTo = unsignedToken.ValidTo,
                        ValidFrom = issuedAt.DateTime,
                        AppName = appleCredentials.AppName!,
                        Endpoint = appleCredentials.Endpoint!
                    };

                    return appleJwtToken;
                }
            }
        }
    }
}
