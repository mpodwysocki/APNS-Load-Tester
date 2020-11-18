# APNS Connection Tester

This is a sample application for load testing connections to APNS Sandbox servers with a given set of credentials.  This allows you to specify a number of values hit against APNS in order to determine optimal HTTP/2 settings.

## Usage

To run this application, you can specify the following items as arguments such as the following or modify the code directly:

1. Pooled Connetion Lifetime - Default Value: 10 seconds
2. Max Connections Per Server - Default Value: 10,000
3. Degrees of Parallelism - Default Value: 50
4. Test Duration - Default Value: 1 minute

In order to connect to APNS, you need to specify the following information in the `Credentials.cs`:

- `AppId`: The Apple App ID
- `AppName`: The Apple App name eg `com.microsoft.exampleapp`
- `KeyId`: The Key ID of the Push Token
- `Token`: The token string from the .p8 file

## License

MIT
