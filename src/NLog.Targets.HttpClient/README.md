# NLog.Targets.HttpClient

[![Version](https://badge.fury.io/nu/NLog.Targets.HttpClient.svg)](https://www.nuget.org/packages/NLog.Targets.HttpClient)
[![AppVeyor](https://img.shields.io/appveyor/ci/NLog/NLog-Targets-Network/master.svg)](https://ci.appveyor.com/project/NLog/NLog-Targets-Network/branch/master)

NLog `HttpClient` target for sending log messages to an HTTP or HTTPS endpoint with support for batching and compression.

If having trouble with output, then check [NLog InternalLogger](https://github.com/NLog/NLog/wiki/Internal-Logging) for clues. See also [Troubleshooting NLog](https://github.com/NLog/NLog/wiki/Logging-Troubleshooting).

## Register Extension

NLog will only recognize the type-alias `HttpClient` when loading from an `NLog.config` file after registering the extension:

```xml
<extensions>
    <add assembly="NLog.Targets.HttpClient"/>
</extensions>
```

Alternative - register from code using the [fluent configuration API](https://github.com/NLog/NLog/wiki/Fluent-Configuration-API):

```csharp
LogManager.Setup().SetupExtensions(ext => {
    ext.RegisterTarget<NLog.Targets.HttpClientTarget>();
});
```