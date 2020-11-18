using System;
using System.Text.Json.Serialization;

namespace ApnsConnectionExperiment
{
    public class AppleJwtToken
    {
        [JsonPropertyName("token")]
        public string Token { get; set; } = string.Empty;

        [JsonPropertyName("appName")]
        public string AppName { get; set; } = string.Empty;

        [JsonPropertyName("validTo")]
        public DateTime ValidTo { get; set; }

        [JsonPropertyName("validFrom")]
        public DateTime ValidFrom { get; set; }

        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; } = string.Empty;

        [JsonIgnore]
        public bool IsTemporary { get; set; }

        public bool IsInitialized()
        {
            return Token != string.Empty && AppName != string.Empty && ValidTo != default && ValidFrom != default;
        }

        public bool IsValid(DateTimeOffset dateTimeOffset)
        {
            return IsInitialized() && ValidTo > dateTimeOffset;
        }
    }
}
