using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace WebApi.Owin.Middleware.Authentication.Token
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public enum SignatureAlgorithm
  {
    None,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512
  }

  internal class JsonWebToken
  {
    private const string AlgHeaderName = "alg";
    private readonly JsonSerializerSettings serializerSettings;

    internal JsonWebToken()
    {
      Header = new Dictionary<string, object> { ["typ"] = "JWT" };
      SignatureAlgorithm = SignatureAlgorithm.HMACSHA256;

      serializerSettings = new JsonSerializerSettings
      {
        Formatting = Formatting.None,
        Converters = { new NumericFormatConverter() }
      };
    }

    public IDictionary<string, object> Header { get; private set; }

    public IDictionary<string, object> Payload { get; set; }

    public SignatureAlgorithm SignatureAlgorithm
    {
      get
      {
        var algName = ((string)Header["alg"]).ToUpperInvariant();
        switch (algName)
        {
          case "NONE":
            return SignatureAlgorithm.None;
          case "HS256":
            return SignatureAlgorithm.HMACSHA256;
          case "HS384":
            return SignatureAlgorithm.HMACSHA384;
          case "HS512":
            return SignatureAlgorithm.HMACSHA512;
          default:
            throw new NotSupportedException($"Algorithm '{algName}' is not supported");
        }
      }
      set
      {
        switch (value)
        {
          case SignatureAlgorithm.None:
            Header[AlgHeaderName] = "none";
            break;
          case SignatureAlgorithm.HMACSHA256:
            Header[AlgHeaderName] = "HS256";
            break;
          case SignatureAlgorithm.HMACSHA384:
            Header[AlgHeaderName] = "HS384";
            break;
          case SignatureAlgorithm.HMACSHA512:
            Header[AlgHeaderName] = "HS512";
            break;
          default:
            throw new ArgumentOutOfRangeException(nameof(value));
        }
      }
    }

    public byte[] Secret { get; set; }

    public static JsonWebToken Create(string serialized, byte[] secret)
    {
      var token = new JsonWebToken {Secret = secret};
      return token.Deserialize(serialized) ? token : null;
    }

    public string Serialize()
    {
      var data = Serialize(Header) + '.' + Serialize(Payload);
      var signature = Sign(data);
      return data + '.' + signature;
    }

    private bool Deserialize(string serialized)
    {
      var parts = serialized.Split('.');
      Header = Deserialize<Dictionary<string, object>>(parts[0]);

      var signature = Sign(parts[0] + '.' + parts[1]);
      if (signature != parts[2]) { return false; }

      Payload = Deserialize<Dictionary<string, object>>(parts[1]);

      return true;
    }

    private string Serialize<T>(T data)
    {
      return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data, serializerSettings)));
    }

    private T Deserialize<T>(string serialized)
    {
      return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(Convert.FromBase64String(serialized)), serializerSettings);
    }

    private string Sign(string data)
    {
      var signature = CreateHMAC()?.ComputeHash(Encoding.UTF8.GetBytes(data));
      return signature == null ? string.Empty : Convert.ToBase64String(signature);
    }

    // ReSharper disable once InconsistentNaming
    private HMAC CreateHMAC()
    {
      switch (SignatureAlgorithm)
      {
        case SignatureAlgorithm.None:
          return null;
        case SignatureAlgorithm.HMACSHA256:
          return new HMACSHA256 { Key = Secret };
        case SignatureAlgorithm.HMACSHA384:
          return new HMACSHA384 { Key = Secret };
        case SignatureAlgorithm.HMACSHA512:
          return new HMACSHA512 { Key = Secret };
        default:
          throw new ArgumentOutOfRangeException(nameof(SignatureAlgorithm));
      }
    }

    private class NumericFormatConverter : JsonConverter<DateTime>
    {
      private static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

      public override void WriteJson(JsonWriter writer, DateTime value, JsonSerializer serializer)
      {
        serializer.Serialize(writer, (int)(value.ToUniversalTime() - epoch).TotalSeconds);
      }

      public override DateTime ReadJson(JsonReader reader, Type objectType, DateTime existingValue, bool hasExistingValue, JsonSerializer serializer)
      {
        return epoch + TimeSpan.FromSeconds(serializer.Deserialize<int>(reader));
      }
    }
  }
}