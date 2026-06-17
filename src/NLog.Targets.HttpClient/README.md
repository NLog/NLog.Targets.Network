# NLog.Targets.HttpClient

[![Version](https://badge.fury.io/nu/NLog.Targets.HttpClient.svg)](https://www.nuget.org/packages/NLog.Targets.HttpClient)
[![AppVeyor](https://img.shields.io/appveyor/ci/NLog/NLog-Targets-Network/master.svg)](https://ci.appveyor.com/project/NLog/NLog-Targets-Network/branch/master)

NLog `HttpClient` target for sending log events to an HTTP or HTTPS endpoint.

* HTTP POST, GET, and custom HTTP methods
* Batching of multiple log events
* JSON array batching
* GZip compression
* Custom request headers
* HTTP authentication
* Client certificates (mTLS)
* Proxy servers

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

## Configuration Example

```xml
<targets>
    <target xsi:type="HttpClient"
            name="http"
            url="https://api.example.com/logs"
            layout="${json-encode:${message}}" />
</targets>

<rules>
    <logger name="*" minlevel="Info" writeTo="http" />
</rules>
```

## Parameters

## Parameters

| Parameter                | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| `url`                    | Required            | Destination URL for HTTP requests.                                                |
| `httpMethod`             | `POST`              | HTTP method used when sending requests.                                           |
| `contentType`            | `application/json`  | Value of the HTTP Content-Type header.                                            |
| `keepAlive`              | `true`              | Reuses TCP connections between requests.                                          |
| `expect100Continue`      | `false`             | Controls HTTP 100-Continue behavior.                                              |
| `lineEnding`             | `LF`                | Line separator used when batching log events.                                     |
| `batchAsJsonArray`       | `false`             | Wraps batched log events in a JSON array. Disables `lineEnding` value             |
| `sendTimeoutSeconds`     | `30`                | HTTP request timeout in seconds.                                                  |
| `networkUserName`        |                     | Username for HTTP authentication. Empty value uses default system credentials.    |
| `networkPassword`        |                     | Password for HTTP authentication.                                                 |
| `sslCertificateFile`     |                     | Client certificate file used for mutual TLS authentication.                       |
| `sslCertificatePassword` |                     | Password for the client certificate.                                              |
| `maxPayloadSizeBytes`    | `40960`             | Max payload size before splitting into multiple HTTP requests. Remember `BatchSize` |
| `compress`               | `None`              | Payload compression mode (`None`, `GZip`, `GZipFast`).                            |
| `proxyUrl`               |                     | Proxy server URL.                                                                 |
| `proxyUser`              |                     | Proxy authentication username.                                                    |
| `proxyPassword`          |                     | Proxy authentication password.                                                    |
| `headers`                |                     | Additional HTTP request headers.                                                  |
| `batchSize`              | `1`                 | Maximum number of log events to send in a single HTTP payload.                    |
| `taskDelayMilliseconds`  | `1`                 | Delay before processing queued log events. Higher value can improve batching      |
| `taskTimeoutSeconds`     | `150`               | Maximum execution time in seconds before cancellation of HTTP request.            |
| `retryCount`             | `0`                 | Number of retry attempts for failed write operations.                             |
| `retryDelayMilliseconds` | `2500`              | Initial delay before retry after failed request. Delay doubles for each retry.    |
| `queueLimit`             | `10000`             | Maximum number of pending requests allowed in the internal queue.                 |
| `overflowAction`         | `Discard`           | Action taken when the internal request queue reaches its limit.                   |


## Custom Headers

Additional HTTP headers can be configured:

```xml
<target xsi:type="HttpClient"
        name="http"
        url="https://api.example.com/logs">

    <header name="X-Api-Key" layout="${gdc:item=ApiKey}" />
    <header name="X-Environment" layout="Production" />

</target>
```

## Client Certificates (mTLS)

Mutual TLS authentication can be enabled using a client certificate:

```xml
<target xsi:type="HttpClient"
        name="http"
        url="https://secure.example.com/logs"
        sslCertificateFile="client.pfx"
        sslCertificatePassword="secret" />
```

## Retry Behavior

The target treats the following status codes as transient failures, that can be retried:

* 408 Request Timeout
* 429 Too Many Requests
* 5xx Server Errors

Client-side failures such as `400 Bad Request` are not retried.

## Notes

* The target internally reuses HttpClient instance for connection pooling.
* HttpClient instance is periodically recycled every 5 mins to handle DNS changes.
