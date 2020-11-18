using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace ApnsConnectionExperiment
{
    public class AppleCredentials
    {
        private const string ApnsCertificateName = "ApnsCertificate";
        private const string CertificateKeyName = "CertificateKey";
        private const string EndpointName = "Endpoint";
        private const string ThumbprintName = "Thumbprint";
        private const string TokenName = "Token";
        private const string KeyIdName = "KeyId";
        private const string AppNameName = "AppName";
        private const string AppIdName = "AppId";

        [JsonIgnore]
        public string ApnsCertificate { get; set; }

        [JsonIgnore]
        public string CertificateKey { get; set; }

        [JsonIgnore]
        public string Endpoint { get; set; }

        [JsonIgnore]
        public string Thumbprint { get; set; }

        [JsonIgnore]
        public string Token { get; set; }

        [JsonIgnore]
        public string KeyId { get; set; }

        [JsonIgnore]
        public string AppName { get; set; }

        [JsonIgnore]
        public string AppId { get; set; }

        public X509Certificate2 GetX509Certificate2()
        {
            if (string.IsNullOrEmpty(this.CertificateKey))
            {
                return new X509Certificate2(Convert.FromBase64String(this.ApnsCertificate!));
            }
            else
            {
                return new X509Certificate2(Convert.FromBase64String(this.ApnsCertificate!), this.CertificateKey);
            }
        }

        [JsonIgnore]
        [IgnoreDataMember]
        public bool IsCertificateBased
        {
            get => !string.IsNullOrEmpty(this.ApnsCertificate);
        }
    }
}
