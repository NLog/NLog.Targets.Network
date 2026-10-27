# NLog Network Target

[![Version](https://badge.fury.io/nu/NLog.Targets.Network.svg)](https://www.nuget.org/packages/NLog.Targets.Network)
[![CI](https://github.com/NLog/NLog.Targets.Network/actions/workflows/ci.yml/badge.svg)](https://github.com/NLog/NLog.Targets.Network/actions/workflows/ci.yml)

The NLog Network Target sends messages over TCP and UDP sockets and supports SSL/TLS.

If you have trouble with output, check [NLog InternalLogger](https://github.com/NLog/NLog/wiki/Internal-Logging) for clues. See also [Troubleshooting NLog](https://github.com/NLog/NLog/wiki/Logging-Troubleshooting).

See the [NLog Wiki - Network Target](https://github.com/NLog/NLog/wiki/Network-target) for available options and examples.

## NLog Syslog Target

NLog SyslogTarget combines the NLog NetworkTarget with NLog SyslogLayout for RFC 5424 and RFC 3164.

See the [NLog Wiki - Syslog Target](https://github.com/NLog/NLog/wiki/Syslog-target) for available options and examples.

## NLog Splunk Target

NLog SplunkTarget combines the NLog NetworkTarget with NLog SplunkLayout.

See the [NLog Wiki - Splunk Target](https://github.com/NLog/NLog/wiki/Splunk-target) for available options and examples.

## NLog GELF Target

NLog GelfTarget combines the NLog NetworkTarget with NLog GelfLayout for Graylog Extended Logging Format (GELF).

See the [NLog Wiki - Gelf Target](https://github.com/NLog/NLog/wiki/Gelf-target) for available options and examples.

## NLog Log4JXml Target

NLog Log4JXmlTarget combines the NLog NetworkTarget with NLog Log4JXmlEventLayout for NLogViewer / Chainsaw / Java Log4J.

See the [NLog Wiki - Log4JXml Target](https://github.com/NLog/NLog/wiki/Log4JXml-target) for available options and examples.

## Register Extension

The `Network` type alias is available when loading from an `NLog.config` file after registering the extension:

```xml
<extensions>
    <add assembly="NLog.Targets.Network"/>
</extensions>
```

Alternatively, register it in code using the [fluent configuration API](https://github.com/NLog/NLog/wiki/Fluent-Configuration-API):

```csharp
LogManager.Setup().SetupExtensions(ext => {
   ext.RegisterTarget<NLog.Targets.NetworkTarget>();
   ext.RegisterTarget<NLog.Targets.Log4JXmlTarget>();
   ext.RegisterTarget<NLog.Targets.GelfTarget>();
   ext.RegisterTarget<NLog.Targets.SplunkTarget>();
   ext.RegisterTarget<NLog.Targets.SyslogTarget>();
   ext.RegisterLayout<NLog.Layouts.Log4JXmlEventLayout>();
   ext.RegisterLayout<NLog.Layouts.GelfLayout>();
   ext.RegisterLayout<NLog.Layouts.SplunkLayout>();
   ext.RegisterLayout<NLog.Layouts.SyslogLayout>();
});
```