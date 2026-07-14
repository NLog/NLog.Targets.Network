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
| _url_                    | Required            | Destination URL for HTTP requests.                                                |
| _layout_                 | Required            | Layout used to render log events into the HTTP request body.                      |
| _httpMethod_             | `POST`              | HTTP method used when sending requests.                                           |
| _contentType_            | `application/json`  | Value of the HTTP Content-Type header.                                            |
| _keepAlive_              | `true`              | Keeps HTTP connections open for reuse in subsequent requests to improve performance. |
| _expect100Continue_      | `false`             | Enables the HTTP Expect: 100-continue handshake before sending the request body.  |
| _sendTimeoutSeconds_     | `30`                | HTTP request timeout in seconds.                                                  |
| _headers_                |                     | Additional HTTP request headers.                                                  |

| Batching and Retry       | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| _batchSize_              | `1`                 | Maximum number of log events to send in a single HTTP payload.                    |
| _compress_               | `None`              | Optional payload compression. Supports `None`, `GZip`, and `GZipFast`.            |
| _lineEnding_             | `LF`                | Line separator used when batching log events.                                     |
| _batchAsJsonArray_       | `false`             | Wraps batched log events in a JSON array instead of separating them with `lineEnding`. |
| _maxPayloadSizeBytes_    | `40960`             | Max payload size before splitting into multiple HTTP requests. Remember `BatchSize` |
| _taskDelayMilliseconds_  | `1`                 | Delay before processing queued log events. Higher value can improve batching      |
| _taskTimeoutSeconds_     | `150`               | Maximum time in seconds before cancellation of HTTP request.                      |
| _retryCount_             | `0`                 | Number of retry attempts for failed write operations.                             |
| _retryDelayMilliseconds_ | `2500`              | Initial delay before retry after failed request. Delay doubles for each retry.    |
| _queueLimit_             | `10000`             | Maximum number of pending log events allowed in the internal queue.               |
| _overflowAction_         | `Discard`           | Action taken when the internal request queue reaches its limit.                   |


| Authentication and Security | Default          | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| _networkUserName_        |                     | Username for HTTP authentication. `_networkUserName = ""` means default NTLM credentials. |
| _networkPassword_        |                     | Password for HTTP authentication.                                                 |
| _sslCertificateFile_     |                     | Client certificate file used for mutual TLS authentication.                       |
| _sslCertificatePassword_ |                     | Password for the client certificate.                                              |
| _proxyUrl_               |                     | Proxy server URL.                                                                 |
| _proxyUser_              |                     | Proxy authentication username.                                                    |
| _proxyPassword_          |                     | Proxy authentication password.                                                    |


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

## Splunk HTTP Event Collector (HEC)

`SplunkLayout` from the [NLog.Targets.Network](https://www.nuget.org/packages/NLog.Targets.Network) package can be used together with the `HttpClient` target to send events to the Splunk HEC `/services/collector/event` endpoint using newline-delimited JSON (NDJSON).

[SplunkLayout](https://github.com/NLog/NLog/wiki/SplunkLayout) renders the complete HEC event, including the outer `time`, `host`, `source`, `sourcetype`, `index`, and nested `event` fields.

The `Authorization` header is mandatory for Splunk HEC: `Authorization: Splunk <hec-token>`

```xml
<nlog>
<extensions>
    <add assembly="NLog.Targets.HttpClient"/>
    <add assembly="NLog.Targets.Network"/>
</extensions>
<targets>
    <target xsi:type="HttpClient"
            name="splunk"
            url="https://splunk-host:8088/services/collector/event"
            batchSize="100">
        <layout xsi:type="SplunkLayout" />
        <header name="Authorization" layout="Splunk ${configsetting:Splunk.Token}" />
    </target>
</targets>
<rules>
    <logger name="*" minlevel="Info" writeTo="splunk" />
</rules>
</nlog>
```

## Notes

* The target internally reuses a single `HttpClient` instance to take advantage of connection pooling.
* The `HttpClient` instance is periodically recycled (every 5 minutes) to detect DNS changes while still benefiting from pooled connections.
