# NLog.Targets.HttpClient

[![Version](https://badge.fury.io/nu/NLog.Targets.HttpClient.svg)](https://www.nuget.org/packages/NLog.Targets.HttpClient)
[![AppVeyor](https://img.shields.io/appveyor/ci/NLog/NLog-Targets-Network/master.svg)](https://ci.appveyor.com/project/NLog/NLog-Targets-Network/branch/master)

NLog `HttpClient` target for sending log events to HTTP or HTTPS endpoints.

* Supports HTTP POST, GET, and custom HTTP methods.
* Batch multiple log events into a single HTTP request.
* Supports batching as JSON arrays or newline-delimited JSON (NDJSON).
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

`HttpClient` and [JsonLayout](https://github.com/NLog/NLog/wiki/JsonLayout) can be used together to send structured log events to HTTP endpoints that accept JSON or newline-delimited JSON (NDJSON), including log collectors such as Fluentd, Fluent Bit, Logstash, and Vector.

```xml
<nlog xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<extensions>
  <add assembly="NLog.Targets.HttpClient"/>
</extensions>

<targets>
  <target xsi:type="HttpClient"
    name="http"
    url="http://localhost:9880/logs_api"
    contentType="application/x-ndjson"
    batchSize="100">
    <header name="User-Agent" layout="NLog-Http-${appdomain:friendly}" />
    <layout xsi:type="JsonLayout" includeEventProperties="true">
      <attribute name="timestamp" layout="${date:format=o:universalTime=true}" />
      <attribute name="hostname" layout="${hostname}" />
      <attribute name="process" layout="${processname}" />
      <attribute name="level" layout="${level}" />
      <attribute name="message" layout="${message:withException=true}" />
    </layout>
  </target>
</targets>

<rules>
    <logger name="*" minlevel="Info" writeTo="http" />
</rules>
</nlog>
```

## Parameters

| Parameter                | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| _url_                    | Required            | EndPoint URL for HTTP / HTTPS requests.                                           |
| _layout_                 | Required            | Layout used to render log events into the HTTP request body.                      |
| _httpMethod_             | `POST`              | HTTP method used when sending requests.                                           |
| _contentType_            | `application/json`  | Value of the HTTP Content-Type header.                                            |
| _headers_                |                     | Additional HTTP request headers.                                                  |

| Batching and Retry       | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| _batchSize_              | `1`                 | Maximum number of log events to send in a single HTTP payload. Increase on high-latency connections. |
| _compress_               | `None`              | Optional compression of the HTTP request payload. Supports `None`, `GZip`, and `GZipFast`. |
| _lineEnding_             | `LF`                | Line separator used between log events when batching.                             |
| _batchAsJsonArray_       | `false`             | Wraps batched log events in a JSON array instead of separating them with `lineEnding`. |
| _maxPayloadSizeBytes_    | `40960`             | Max payload size before splitting into multiple HTTP requests when using `BatchSize` |
| _taskDelayMilliseconds_  | `1`                 | Delay before processing queued log events. Increasing value can improve batching. |
| _taskTimeoutSeconds_     | `150`               | Maximum lifetime in seconds for the entire task performing the HTTP request.      |
| _retryCount_             | `0`                 | Number of retry attempts for failed write operations.                             |
| _retryDelayMilliseconds_ | `2500`              | Initial delay before retry after failed request. Delay doubles for each retry.    |
| _queueLimit_             | `10000`             | Maximum number of pending log events allowed in the internal queue.               |
| _overflowAction_         | `Discard`           | Action taken when the internal queue reaches its limit (Grow / Block / Discard).  |


| Network and Security     | Default             | Description                                                                       |
| ------------------------ | ------------------- | ----------------------------------------------------------------------------------|
| _keepAlive_              | `true`              | Keeps HTTP connections open for reuse by subsequent requests for better performance. |
| _expect100Continue_      | `false`             | Enables the HTTP 100-Continue handshake before sending the request body, but can increase latency. |
| _sendTimeoutSeconds_     | `30`                | HTTP request timeout in seconds.                                                  |
| _networkUserName_        |                     | Username for HTTP authentication. Explicit blank value (`networkUserName=""`) means default NTLM credentials. |
| _networkPassword_        |                     | Password for HTTP authentication.                                                 |
| _sslCertificateFile_     |                     | Client certificate file used for mutual TLS authentication.                       |
| _sslCertificatePassword_ |                     | Password for the client certificate file.                                         |
| _sslCertificateThumbprint_ |                   | Thumbprint of a client certificate from X509Store (CurrentUser, then LocalMachine). Alternative to `sslCertificateFile`. |
| _proxyUrl_               |                     | Proxy server URL.                                                                 |
| _proxyUser_              |                     | Proxy authentication username.                                                    |
| _proxyPassword_          |                     | Proxy authentication password.                                                    |

## Splunk HTTP Event Collector (HEC)

`SplunkLayout` from the [NLog.Targets.Network](https://www.nuget.org/packages/NLog.Targets.Network) package can be used together with the `HttpClient` target to send events to the Splunk HEC `/services/collector/event` endpoint using newline-delimited JSON (NDJSON).

[SplunkLayout](https://github.com/NLog/NLog/wiki/SplunkLayout) renders the complete HEC event, including the outer `time`, `host`, `source`, `sourcetype`, `index`, and nested `event` fields.

The `Authorization` header is mandatory for Splunk HEC: `Authorization: Splunk <hec-token>`

```xml
<nlog xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<extensions>
  <add assembly="NLog.Targets.HttpClient"/>
  <add assembly="NLog.Targets.Network"/>
</extensions>
<targets>
  <target xsi:type="HttpClient"
    name="splunk"
    url="https://splunk-host:8088/services/collector/event"
    batchSize="100">
    <header name="Authorization" layout="Splunk ${configsetting:Splunk.Token}" />
    <layout xsi:type="SplunkLayout" />
  </target>
</targets>
<rules>
    <logger name="*" minlevel="Info" writeTo="splunk" />
</rules>
</nlog>
```

## OpenSearch Bulk API

`EcsLayout` from the [Elastic.CommonSchema.NLog](https://www.nuget.org/packages/Elastic.CommonSchema.NLog) can be used together with the `HttpClient` target to send ECS-formatted log events to OpenSearch using the Bulk API.

`EcsLayout` produces the ECS-formatted JSON document, while [CompoundLayout](https://github.com/NLog/NLog/wiki/CompoundLayout) adds the Bulk API action metadata. The `&#xA;` is an explicit LF required to separate the action and document lines in the NDJSON payload for Bulk API. The URL `/logs/_bulk` supplies the default target index, so the Bulk API action does not need to provide an `index` value.

```xml
<nlog xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<extensions>
  <add assembly="NLog.Targets.HttpClient"/>
  <add assembly="Elastic.CommonSchema.NLog"/>
</extensions>
<targets>
  <target xsi:type="HttpClient"
    name="opensearch"
    url="https://localhost:9200/logs/_bulk"
    contentType="application/x-ndjson"
    batchSize="100">
    <layout xsi:type="CompoundLayout">
        <layout xsi:type="SimpleLayout" text="{&quot;index&quot;:{}}&#xA;" />
        <layout xsi:type="EcsLayout" />
    </layout>
  </target>
</targets>
<rules>
    <logger name="*" minlevel="Info" writeTo="opensearch" />
</rules>
</nlog>
```

For production use, consider targeting a write index alias managed by your rollover/index lifecycle strategy rather than a permanently fixed index name. Authentication can be configured using the standard `HttpClient` target authentication and header options.

Notice OpenSearch Bulk API can return HTTP 200 even when individual bulk operations fail. The HttpClient target retries HTTP-level failures; it does not inspect the Bulk API response for per-document failures.

Notice that export depends on in-memory queue, where LogEvents can be lost on application-crash / -exit (without correct flush/shutdown). If higher guarantee of delivery is required, then consider using [Elastic.CommonSchema.NLog](https://www.nuget.org/packages/Elastic.CommonSchema.NLog) together with NLog FileTarget and use [filebeat](https://www.elastic.co/beats/filebeat) to ship these logs.

## Client Certificates (mTLS)

Mutual TLS authentication can be enabled using a client certificate:

```xml
<target xsi:type="HttpClient"
        name="http"
        url="https://secure.example.com/logs"
        sslCertificateFile="client.pfx"
        sslCertificatePassword="secret" />
```

Alternatively load the client certificate from the Windows certificate store by thumbprint:

```xml
<target xsi:type="HttpClient"
        name="http"
        url="https://secure.example.com/logs"
        sslCertificateThumbprint="A1B2C3D4E5F6..." />
```

## Retry Behavior

The target treats the following HTTP response status codes as transient failures, that can be retried:

* 408 Request Timeout
* 429 Too Many Requests
* 5xx Server Errors

Client-side failures such as `400 Bad Request` are not retried.

## Notes

* The target internally reuses a single `HttpClient` instance to take advantage of connection pooling.
* The `HttpClient` instance is periodically recycled (every 5 minutes) to detect DNS changes while still benefiting from pooled connections.
