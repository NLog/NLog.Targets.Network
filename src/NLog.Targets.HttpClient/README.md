# NLog.Targets.HttpClient

[![Version](https://badge.fury.io/nu/NLog.Targets.HttpClient.svg)](https://www.nuget.org/packages/NLog.Targets.HttpClient)
[![AppVeyor](https://img.shields.io/appveyor/ci/NLog/NLog-Targets-Network/master.svg)](https://ci.appveyor.com/project/NLog/NLog-Targets-Network/branch/master)

NLog `HttpClient` target for sending log events to an HTTP or HTTPS endpoint.

* Supports HTTP POST, GET, and custom HTTP methods.
* Batch multiple log events into a single HTTP request.
* Supports batching as JSON arrays or Newline Delimited JSON (NDJSON).
* GZip compression
* Custom request headers
* HTTP authentication
* Client certificates (mTLS)
* HTTP proxy support.

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

| Parameter                | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| `url`                    | Required            | Destination URL for HTTP requests.                                                |
| `layout`                 | Required            | Layout used to render log events into the HTTP request body.                      |
| `httpMethod`             | `POST`              | HTTP method used when sending requests.                                           |
| `contentType`            | `application/json`  | Value of the HTTP Content-Type header.                                            |
| `keepAlive`              | `true`              | Keeps HTTP connections open for reuse in subsequent requests to improve performance. |
| `expect100Continue`      | `false`             | Enables the HTTP Expect: 100-continue handshake before sending the request body.  |
| `sendTimeoutSeconds`     | `30`                | HTTP request timeout in seconds.                                                  |
| `headers`                |                     | Additional HTTP request headers.                                                  |

| Batching and Retry       | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| `batchSize`              | `1`                 | Maximum number of log events to send in a single HTTP payload.                    |
| `compress`               | `None`              | Optional payload compression. Supports `None`, `GZip`, and `GZipFast`.            |
| `lineEnding`             | `LF`                | Line separator used when batching log events.                                     |
| `batchAsJsonArray`       | `false`             | Wraps batched log events in a JSON array instead of separating them with `lineEnding`. |
| `maxPayloadSizeBytes`    | `40960`             | Max payload size before splitting into multiple HTTP requests. Remember `BatchSize` |
| `taskDelayMilliseconds`  | `1`                 | Delay before processing queued log events. Higher value can improve batching      |
| `taskTimeoutSeconds`     | `150`               | Maximum time in seconds before cancellation of HTTP request.                      |
| `retryCount`             | `0`                 | Number of retry attempts for failed write operations.                             |
| `retryDelayMilliseconds` | `2500`              | Initial delay before retry after failed request. Delay doubles for each retry.    |
| `queueLimit`             | `10000`             | Maximum number of pending log events allowed in the internal queue.               |
| `overflowAction`         | `Discard`           | Action taken when the internal request queue reaches its limit.                   |


| Authentication and Security | Default          | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| `networkUserName`        |                     | Username for HTTP authentication. `networkUserName = ""` means default NTLM credentials. |
| `networkPassword`        |                     | Password for HTTP authentication.                                                 |
| `sslCertificateFile`     |                     | Client certificate file used for mutual TLS authentication.                       |
| `sslCertificatePassword` |                     | Password for the client certificate.                                              |
| `proxyUrl`               |                     | Proxy server URL.                                                                 |
| `proxyUser`              |                     | Proxy authentication username.                                                    |
| `proxyPassword`          |                     | Proxy authentication password.                                                    |


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

* The target internally reuses a single `HttpClient` instance to take advantage of connection pooling.
* The `HttpClient` instance is periodically recycled (every 5 minutes) to detect DNS changes while still benefiting from pooled connections.
