# NLog.Targets.OpenTelemetryHttp

[![Version](https://badge.fury.io/nu/NLog.Targets.OpenTelemetryHttp.svg)](https://www.nuget.org/packages/NLog.Targets.OpenTelemetryHttp)
[![AppVeyor](https://img.shields.io/appveyor/ci/NLog/NLog-Targets-Network/master.svg)](https://ci.appveyor.com/project/NLog/NLog-Targets-Network/branch/master)

NLog `OpenTelemetry` target for sending log messages to an OpenTelemetry OTLP endpoint using protobuf encoding over HTTP (OTLP/HTTP).

If having trouble with output, then check [NLog InternalLogger](https://github.com/NLog/NLog/wiki/Internal-Logging) for clues. See also [Troubleshooting NLog](https://github.com/NLog/NLog/wiki/Logging-Troubleshooting).

See also:

* https://opentelemetry.io/docs/specs/otlp/#otlphttp
* https://opentelemetry.io/docs/specs/otel/protocol/exporter/

## Register Extension

NLog will only recognize the type-alias `OpenTelemetry` when loading from an `NLog.config` file after registering the extension:

```xml
<extensions>
    <add assembly="NLog.Targets.OpenTelemetryHttp"/>
</extensions>
```

Alternative - register from code using the [fluent configuration API](https://github.com/NLog/NLog/wiki/Fluent-Configuration-API):

```csharp
LogManager.Setup().SetupExtensions(ext => {
    ext.RegisterTarget<NLog.Targets.OpenTelemetryHttpTarget>();
});
```

## Configuration Example

Typical endpoint URL is `http://localhost:4318/v1/logs`.

Supports standard OpenTelemetry environment variables as fallback defaults:
`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_LOGS_HEADERS`,
`OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_LOGS_COMPRESSION`, `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_EXPORTER_OTLP_LOGS_TIMEOUT`,
`OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`.

```xml
<targets>
    <target xsi:type="OpenTelemetry"
            name="otel"
            url="http://localhost:4318/v1/logs"
            serviceName="MyApplication"
            layout="${message}" />
</targets>

<rules>
    <logger name="*" minlevel="Info" writeTo="otel" />
</rules>
```

## Parameters

## Parameters

| Parameter                | Default                        | Description                                                                  |
| ------------------------ | -------------------------------| -----------------------------------------------------------------------------|
| `url`                    | OTEL_EXPORTER_OTLP_ENDPOINT    | OTLP/HTTP endpoint URL. Automatically append `/v1/logs` when missing         |
| `serviceName`            | `${appdomain:format=Friendly}` | OpenTelemetry `service.name` resource attribute.                             |
| `serviceVersion`         | `${assembly-version:Default=}` | OpenTelemetry `service.version` resource attribute.                          |
| `hostName`               | `${hostname}`                  | OpenTelemetry `host.name` resource attribute.                                |
| `scopeName`              | `NLog`                         | OpenTelemetry instrumentation scope name.                                    |
| `layout`                 | `${message}`                   | Layout used for the OTLP log body (message text).                            |
| `traceId`                | `${activity:property=TraceId}` | Layout used to populate the OTLP LogRecord TraceId field.                    |
| `spanId`                 | `${activity:property=SpanId}`  | Layout used to populate the OTLP LogRecord SpanId field.                     |
| `compress`               | `None`                         | Optional payload compression. Supports `None`, `GZip`, and `GZipFast`.       |
| `batchSize`              | `200`                          | Maximum number of log events processed in a batch before transmission.       |
| `includeEventProperties` | `true`                         | Includes NLog event properties as OpenTelemetry log attributes.              |
| `sendTimeoutSeconds`     | 30                             | HTTP request timeout.                                                        |
| `maxPayloadSizeBytes`    | 40960                          | Maximum payload size before automatic request chunking occurs.               |
| `sslCertificateFile`     |                                | Client certificate file used for mutual TLS authentication.                  |
| `sslCertificatePassword` |                                | Password for the client certificate.                                         |
| `proxyUrl`               |                                | Proxy server URL.                                                            |
| `proxyUser`              |                                | Proxy authentication username.                                               |
| `proxyPassword`          |                                | Proxy authentication password.                                               |
| `batchSize`              | `200`                          | Maximum number of log events to send in a single HTTP payload.               |
| `taskDelayMilliseconds`  | `50`                           | Delay before processing queued log events. Higher value can improve batching |
| `taskTimeoutSeconds`     | `150`                          | Maximum execution time in seconds before cancellation of HTTP request.       |
| `retryCount`             | `3`                            | Number of retry attempts for failed write operations.                        |
| `retryDelayMilliseconds` | `2500`                         | Initial delay before retry after failed request. Delay doubles for each retry. |
| `queueLimit`             | `10000`                        | Maximum number of pending requests allowed in the internal queue.            |
| `overflowAction`         | `Discard`                      | Action taken when the internal request queue reaches its limit.              |


## Resource Attributes

Additional OpenTelemetry resource attributes can be configured using `resourceAttribute` entries:

```xml
<target xsi:type="OpenTelemetry" name="otel">

    <resourceAttribute name="service.namespace" layout="Backend" />
    <resourceAttribute name="deployment.environment" layout="Production" />

</target>
```

These attributes are attached to every exported log record.

## OpenTelemetry Environment Variables

The target automatically resolves standard OpenTelemetry environment variables when equivalent target properties have not been explicitly configured.

### Endpoint

Order of precedence:

1. `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`
2. `OTEL_EXPORTER_OTLP_ENDPOINT`

When `OTEL_EXPORTER_OTLP_ENDPOINT` is used, `/v1/logs` is automatically appended.

### Headers

Order of precedence:

1. `OTEL_EXPORTER_OTLP_LOGS_HEADERS`
2. `OTEL_EXPORTER_OTLP_HEADERS`

Example:

```text
OTEL_EXPORTER_OTLP_HEADERS=api-key=my-secret-key
```

### Compression

Order of precedence:

1. `OTEL_EXPORTER_OTLP_LOGS_COMPRESSION`
2. `OTEL_EXPORTER_OTLP_COMPRESSION`

Supported values:

* `gzip`
* `none`

### Timeout

Order of precedence:

1. `OTEL_EXPORTER_OTLP_LOGS_TIMEOUT`
2. `OTEL_EXPORTER_OTLP_TIMEOUT`

Timeout values are specified in milliseconds.

### Service Name

`OTEL_SERVICE_NAME`

Overrides the `service.name` value from `OTEL_RESOURCE_ATTRIBUTES`.

### Resource Attributes

`OTEL_RESOURCE_ATTRIBUTES`

Example:

```text
OTEL_RESOURCE_ATTRIBUTES=service.namespace=Backend,deployment.environment=Production
```

The special attribute:

```text
service.name
```

is automatically mapped to the `serviceName` property.

### Client Certificate

Order of precedence:

1. `OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE`
2. `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`

Used to configure mutual TLS authentication.
