//
// Copyright (c) 2004-2024 Jaroslaw Kowalski <jaak@jkowalski.net>, Kim Christensen, Julian Verdurmen
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// * Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of Jaroslaw Kowalski nor the names of its
//   contributors may be used to endorse or promote products derived from this
//   software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//

namespace NLog.Targets
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Net.Http;
    using System.Threading;
    using System.Threading.Tasks;
    using NLog.Config;
    using NLog.Internal;
    using NLog.Layouts;

    /// <summary>
    /// Sends log messages to an OpenTelemetry OTLP endpoint using protobuf encoding over HTTP.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The target serializes log events into the OTLP ExportLogsServiceRequest protobuf format
    /// and sends them via HTTP POST. Typical endpoint URL is <c>http://localhost:4318/v1/logs</c>.
    /// </para>
    /// <para>
    /// Supports standard OpenTelemetry environment variables as fallback defaults:
    /// <c>OTEL_EXPORTER_OTLP_ENDPOINT</c>, <c>OTEL_EXPORTER_OTLP_LOGS_ENDPOINT</c>,
    /// <c>OTEL_EXPORTER_OTLP_HEADERS</c>, <c>OTEL_EXPORTER_OTLP_LOGS_HEADERS</c>,
    /// <c>OTEL_EXPORTER_OTLP_COMPRESSION</c>, <c>OTEL_EXPORTER_OTLP_LOGS_COMPRESSION</c>,
    /// <c>OTEL_EXPORTER_OTLP_TIMEOUT</c>, <c>OTEL_EXPORTER_OTLP_LOGS_TIMEOUT</c>,
    /// <c>OTEL_EXPORTER_OTLP_PROTOCOL</c>, <c>OTEL_EXPORTER_OTLP_LOGS_PROTOCOL</c>,
    /// <c>OTEL_SERVICE_NAME</c>, <c>OTEL_RESOURCE_ATTRIBUTES</c>.
    /// Environment variables are resolved using NLog <c>${environment}</c> layout renderer.
    /// </para>
    /// <a href="https://opentelemetry.io/docs/specs/otlp/#otlphttp">See OTLP/HTTP Specification</a>
    /// <a href="https://opentelemetry.io/docs/specs/otel/protocol/exporter/">See OTLP Exporter Configuration</a>
    /// </remarks>
    [Target("OpenTelemetry")]
    [Target("OpenTelemetryHttp")]
    public class OpenTelemetryHttpTarget : HttpClientTarget
    {
        private static readonly SimpleLayout _defaultServiceName = new SimpleLayout("${appdomain:format=Friendly}");
        private static readonly string EmptyTraceIdToHexString = default(System.Diagnostics.ActivityTraceId).ToHexString();
        private static readonly string EmptySpanIdToHexString = default(System.Diagnostics.ActivitySpanId).ToHexString();

        private OtlpProtobufSerializer _serializer = new OtlpProtobufSerializer();
        private Uri? _logsUrl;
        private readonly Stack<MemoryStream> _memoryStreamPool = new Stack<MemoryStream>();
        private List<MemoryStream>? _activeChunkStreams = new List<MemoryStream>();

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenTelemetryHttpTarget"/> class.
        /// </summary>
        public OpenTelemetryHttpTarget()
        {
            ContentType = "application/x-protobuf"; // application/json not supported, only protobuf as OTLP_PROTOCOL
            IncludeEventProperties = true;
            BatchSize = 200;                // Consider doubling this if enabling compression
            TaskDelayMilliseconds = 50;     // Small delay to improve chance of batching and reducing number of HTTP requests.
            RetryDelayMilliseconds = 2500;  // Notice OTel SDK initial backoff is 5 secs
            RetryCount = 3;                 // Notice OTel SDK default max 5 retries
        }

        /// <summary>
        /// Gets or sets the OTLP resource <c>service.name</c> attribute value.
        /// </summary>
        /// <remarks>Default: <c>${appdomain:format=Friendly}</c>. Defaults to <c>Unknown</c> when empty value</remarks>
        public Layout ServiceName { get; set; } = _defaultServiceName;

        /// <summary>
        /// Gets or sets the OpenTelemetry instrumentation scope name.
        /// </summary>
        /// <remarks>Default: <see langword="NLog"/></remarks>
        public string ScopeName { get; set; } = "NLog";

        /// <summary>
        /// Gets or sets additional OpenTelemetry resource attributes.
        /// These attributes are included with every exported OTLP log record.
        /// </summary>
        [ArrayParameter(typeof(TargetPropertyWithContext), "resourceattribute")]
        public IList<TargetPropertyWithContext> ResourceAttributes { get; set; } = new List<TargetPropertyWithContext>();

        /// <summary>
        /// Gets or sets the layout used to populate the OTLP LogRecord TraceId field.
        /// </summary>
        /// <remarks>Default: <c>${activity:property=TraceId}</c> — captures Activity.Current TraceId on the logging thread.</remarks>
        public Layout<System.Diagnostics.ActivityTraceId?>? TraceId { get; set; } = Layout<System.Diagnostics.ActivityTraceId?>.FromMethod(static evt => System.Diagnostics.Activity.Current?.TraceId is System.Diagnostics.ActivityTraceId activityTraceId && !ReferenceEquals(EmptyTraceIdToHexString, activityTraceId.ToHexString()) ? activityTraceId : null);

        /// <summary>
        /// Gets or sets the layout used to populate the OTLP LogRecord SpanId field.
        /// </summary>
        /// <remarks>Default: <c>${activity:property=SpanId}</c> — captures Activity.Current SpanId on the logging thread.</remarks>
        public Layout<System.Diagnostics.ActivitySpanId?>? SpanId { get; set; } = Layout<System.Diagnostics.ActivitySpanId?>.FromMethod(static evt => System.Diagnostics.Activity.Current?.SpanId is System.Diagnostics.ActivitySpanId activitySpanId && !ReferenceEquals(EmptySpanIdToHexString, activitySpanId.ToHexString()) ? activitySpanId : null);

        /// <inheritdoc />
        protected override void InitializeTarget()
        {
            ResolveOtlpEnvironmentVariables();
            _serializer = new OtlpProtobufSerializer
            {
                TraceId = TraceId,
                SpanId = SpanId,
            };
            _logsUrl = null;
            base.InitializeTarget();
        }

        /// <inheritdoc />
        protected override async Task WriteAsyncTask(IList<LogEventInfo> logEvents, CancellationToken cancellationToken)
        {
            if (logEvents.Count == 0)
                return;

            if (_logsUrl is null)
            {
                var urlStr = RenderLogEvent(Url, logEvents[0]);
                if (!urlStr.EndsWith("/logs/", StringComparison.OrdinalIgnoreCase) && !urlStr.EndsWith("/logs", StringComparison.OrdinalIgnoreCase))
                    urlStr = urlStr.TrimEnd('/') + "/v1/logs";
                if (!Uri.TryCreate(urlStr, UriKind.Absolute, out _logsUrl))
                    NLog.Common.InternalLogger.Warn("{0}: Invalid OTLP endpoint URL: {1}", this, urlStr);
            }

            var chunks = Interlocked.Exchange(ref _activeChunkStreams, null) ?? new List<MemoryStream>();
            try
            {
                if (Compress != HttpCompressionType.None)
                    await WriteCompressedAsync(logEvents, chunks, cancellationToken).ConfigureAwait(false);
                else
                    await WriteRawAsync(logEvents, chunks, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                for (int i = 0; i < chunks.Count; i++)
                    ReturnMemoryStream(chunks[i]);
                chunks.Clear();
                Interlocked.Exchange(ref _activeChunkStreams, chunks);
            }
        }

        private async Task WriteRawAsync(IList<LogEventInfo> logEvents, List<MemoryStream> chunks, CancellationToken cancellationToken)
        {
            List<Task<HttpResponseMessage>>? pendingTasks = null;
            var output = RentMemoryStream();
            chunks.Add(output);

            for (int i = 0; i < logEvents.Count; i++)
            {
                SerializeLogEvent(logEvents[i], output);

                if (output.Length >= MaxPayloadSizeBytes && i < logEvents.Count - 1)
                {
                    var sendTask = HttpClientSendAsync(_logsUrl, BuildHttpContent(output), cancellationToken);
                    pendingTasks ??= new List<Task<HttpResponseMessage>>();
                    pendingTasks.Add(sendTask);
                    output = RentMemoryStream();
                    chunks.Add(output);
                }
            }

            await SendLastChunkAndAwaitPendingAsync(BuildHttpContent(output), pendingTasks, cancellationToken).ConfigureAwait(false);
        }

        private async Task SendLastChunkAndAwaitPendingAsync(HttpContent lastContent, List<Task<HttpResponseMessage>>? pendingTasks, CancellationToken cancellationToken)
        {
            using var lastResponse = await HttpClientSendAsync(_logsUrl, lastContent, cancellationToken).ConfigureAwait(false);
            if (pendingTasks != null)
            {
                if (pendingTasks.Count == 1)
                {
                    using var response = await pendingTasks[0].ConfigureAwait(false);
                }
                else
                {
                    var responses = await Task.WhenAll(pendingTasks).ConfigureAwait(false);
                    foreach (var response in responses)
                        response?.Dispose();
                }
            }
        }

        private static ByteArrayContent BuildHttpContent(MemoryStream output)
        {
            return new ByteArrayContent(output.GetBuffer(), 0, (int)output.Length);
        }

        private async Task WriteCompressedAsync(IList<LogEventInfo> logEvents, List<MemoryStream> chunks, CancellationToken cancellationToken)
        {
            List<Task<HttpResponseMessage>>? pendingTasks = null;
            var compressionLevel = Compress == HttpCompressionType.GZipFast ? CompressionLevel.Fastest : CompressionLevel.Optimal;
            var eventBuffer = RentMemoryStream();
            var compressedOutput = RentMemoryStream();
            chunks.Add(compressedOutput);
            GZipStream? gzipStream = new GZipStream(compressedOutput, compressionLevel, leaveOpen: true);
            try
            {
                for (int i = 0; i < logEvents.Count; i++)
                {
                    eventBuffer.Position = 0;
                    eventBuffer.SetLength(0);
                    SerializeLogEvent(logEvents[i], eventBuffer);
                    gzipStream.Write(eventBuffer.GetBuffer(), 0, (int)eventBuffer.Length);

                    if (compressedOutput.Length >= MaxPayloadSizeBytes && i < logEvents.Count - 1)
                    {
                        gzipStream.Dispose();
                        gzipStream = null;
                        var sendTask = HttpClientSendAsync(_logsUrl, BuildGzipContent(compressedOutput), cancellationToken);
                        pendingTasks ??= new List<Task<HttpResponseMessage>>();
                        pendingTasks.Add(sendTask);
                        compressedOutput = RentMemoryStream();
                        chunks.Add(compressedOutput);
                        gzipStream = new GZipStream(compressedOutput, compressionLevel, leaveOpen: true);
                    }
                }

                gzipStream.Dispose();
                gzipStream = null;
            }
            finally
            {
                gzipStream?.Dispose();
                ReturnMemoryStream(eventBuffer);
            }

            await SendLastChunkAndAwaitPendingAsync(BuildGzipContent(compressedOutput), pendingTasks, cancellationToken).ConfigureAwait(false);
        }

        private static HttpContent BuildGzipContent(MemoryStream compressedPayload)
        {
            var content = new ByteArrayContent(compressedPayload.GetBuffer(), 0, (int)compressedPayload.Length);
            content.Headers.ContentEncoding.Add("gzip");
            return content;
        }

        private void SerializeLogEvent(LogEventInfo logEvent, MemoryStream output)
        {
            using var builder = _serializer.BeginRecord(output);

            var serviceName = RenderLogEvent(ServiceName, logEvent);
            if (serviceName is null || string.IsNullOrWhiteSpace(serviceName))
                serviceName = "Unknown";
            builder.AddResourceAttribute("service.name", serviceName);

            for (int j = 0; j < ResourceAttributes.Count; j++)
            {
                var attr = ResourceAttributes[j];
                if (attr.Name is null || string.IsNullOrWhiteSpace(attr.Name))
                    continue;
                var value = RenderLogEvent(attr.Layout, logEvent);
                if (!attr.IncludeEmptyValue && string.IsNullOrWhiteSpace(value))
                    continue;
                builder.AddResourceAttribute(attr.Name, value);
            }

            var properties = GetLogEventProperties(logEvent);
            if (properties is null && (IncludeEventProperties && logEvent.HasProperties))
            {
                builder.AddScopeLogs(ScopeName, logEvent, RenderLogEvent(Layout, logEvent), logEvent.Properties);
            }
            else
            {
                builder.AddScopeLogs(ScopeName, logEvent, RenderLogEvent(Layout, logEvent), properties);
            }
        }

        IEnumerable<KeyValuePair<string, object?>>? GetLogEventProperties(LogEventInfo logEvent)
        {
            if (IncludeScopeProperties || IncludeGdc || (ContextProperties.Count > 0 && IncludeEventProperties && logEvent.HasProperties))
            {
                return GetAllProperties(logEvent);
            }
            else if (ContextProperties.Count > 0)
            {
                return GetLogEventContextProperties(logEvent);
            }
            else
            {
                return null;
            }
        }

        private IEnumerable<KeyValuePair<string, object?>> GetLogEventContextProperties(LogEventInfo logEvent)
        {
            for (int i = 0; i < ContextProperties.Count; i++)
            {
                var prop = ContextProperties[i];
                var value = RenderLogEvent(prop.Layout, logEvent);
                if (!prop.IncludeEmptyValue && string.IsNullOrWhiteSpace(value))
                    continue;
                yield return new KeyValuePair<string, object?>(prop.Name, value);
            }
        }

        private MemoryStream RentMemoryStream()
        {
            lock (_memoryStreamPool)
                return _memoryStreamPool.Count > 0 ? _memoryStreamPool.Pop() : new MemoryStream(4096);
        }

        private void ReturnMemoryStream(MemoryStream stream)
        {
            if (stream.Capacity < 1_000_000)
            {
                stream.Position = 0;
                stream.SetLength(0);
                lock (_memoryStreamPool)
                    _memoryStreamPool.Push(stream);
            }
            else
            {
                stream.Dispose();
            }
        }


        #region OTLP Environment Variable Support

        /// <summary>
        /// Resolves standard OpenTelemetry environment variables as fallback defaults.
        /// Signal-specific variables (e.g. <c>OTEL_EXPORTER_OTLP_LOGS_ENDPOINT</c>) take precedence
        /// over generic ones (e.g. <c>OTEL_EXPORTER_OTLP_ENDPOINT</c>).
        /// Properties that have been explicitly configured are not overridden.
        /// </summary>
        private void ResolveOtlpEnvironmentVariables()
        {
            // Capture whether ServiceName is still at its default value before any env var processing.
            // OTEL_SERVICE_NAME must take precedence over service.name in OTEL_RESOURCE_ATTRIBUTES,
            // but must not override an explicitly configured ServiceName.
            bool serviceNameIsDefault = ReferenceEquals(ServiceName, _defaultServiceName);

            // Endpoint: OTEL_EXPORTER_OTLP_LOGS_ENDPOINT > OTEL_EXPORTER_OTLP_ENDPOINT + "/v1/logs"
            if (Url is null || ReferenceEquals(Url, Layout.Empty))
            {
                var logsEndpoint = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT");
                if (string.IsNullOrWhiteSpace(logsEndpoint))
                {
                    var baseEndpoint = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_ENDPOINT");
                    if (!string.IsNullOrWhiteSpace(baseEndpoint))
                    {
                        logsEndpoint = baseEndpoint!.TrimEnd('/') + "/v1/logs";
                    }
                }
                if (!string.IsNullOrWhiteSpace(logsEndpoint))
                {
                    Url = logsEndpoint;
                }
            }

            // Headers: OTEL_EXPORTER_OTLP_LOGS_HEADERS > OTEL_EXPORTER_OTLP_HEADERS
            if (Headers.Count == 0)
            {
                var headersStr = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_LOGS_HEADERS");
                if (string.IsNullOrWhiteSpace(headersStr))
                    headersStr = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_HEADERS");
                if (!string.IsNullOrWhiteSpace(headersStr))
                    ParseOtlpHeaders(headersStr!);
            }

            // Compression: OTEL_EXPORTER_OTLP_LOGS_COMPRESSION > OTEL_EXPORTER_OTLP_COMPRESSION
            if (Compress == HttpCompressionType.None)
            {
                var compression = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_LOGS_COMPRESSION");
                if (string.IsNullOrWhiteSpace(compression))
                    compression = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_COMPRESSION");
                if (string.Equals(compression?.Trim(), "gzip", StringComparison.OrdinalIgnoreCase))
                    Compress = HttpCompressionType.GZip;
                else if (string.Equals(compression?.Trim(), "none", StringComparison.OrdinalIgnoreCase))
                    Compress = HttpCompressionType.None;
            }

            // Timeout: OTEL_EXPORTER_OTLP_LOGS_TIMEOUT > OTEL_EXPORTER_OTLP_TIMEOUT (milliseconds)
            {
                var timeoutStr = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT");
                if (string.IsNullOrWhiteSpace(timeoutStr))
                    timeoutStr = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_TIMEOUT");
                if (!string.IsNullOrWhiteSpace(timeoutStr) && int.TryParse(timeoutStr!.Trim(), out var timeoutMs) && timeoutMs > 0)
                    SendTimeoutSeconds = Math.Max(1, timeoutMs / 1000);
            }

            // Resource Attributes: OTEL_RESOURCE_ATTRIBUTES (format: key1=value1,key2=value2)
            if (ResourceAttributes.Count == 0)
            {
                var resourceAttrs = GetEnvironmentValueFromLayout("OTEL_RESOURCE_ATTRIBUTES");
                if (!string.IsNullOrWhiteSpace(resourceAttrs))
                    ParseOtlpResourceAttributes(resourceAttrs!);
            }

            // Service Name: OTEL_SERVICE_NAME takes precedence over service.name in OTEL_RESOURCE_ATTRIBUTES
            if (serviceNameIsDefault)
            {
                var otelServiceName = GetEnvironmentValueFromLayout("OTEL_SERVICE_NAME");
                if (!string.IsNullOrWhiteSpace(otelServiceName))
                {
                    ServiceName = otelServiceName;
                }
            }

#if !NETFRAMEWORK || NET471_OR_GREATER
            // Client Certificate: OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE > OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
            if (SslCertificateFile is null)
            {
                var clientCert = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE");
                if (string.IsNullOrWhiteSpace(clientCert))
                    clientCert = GetEnvironmentValueFromLayout("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE");
                if (!string.IsNullOrWhiteSpace(clientCert))
                    SslCertificateFile = clientCert;
            }
#endif
        }

        /// <summary>
        /// Reads an environment variable using NLog <c>${environment}</c> layout renderer.
        /// </summary>
        private static string GetEnvironmentValueFromLayout(string variableName)
        {
            try
            {
                Layout layout = "${environment:" + variableName + "}";
                return layout.Render(LogEventInfo.CreateNullEvent());
            }
            catch (Exception ex)
            {
                NLog.Common.InternalLogger.Debug(ex, "OpenTelemetryHttpTarget: Failed to read environment variable '{0}'", variableName);
                return string.Empty;
            }
        }

        /// <summary>
        /// Parses OTLP headers from a W3C Baggage-like format (<c>key1=value1,key2=value2</c>)
        /// and adds them to <see cref="HttpClientTarget.Headers"/>.
        /// </summary>
        private void ParseOtlpHeaders(string headersStr)
        {
            foreach (var (key, value) in ParseKeyValuePairs(headersStr))
                Headers.Add(new TargetPropertyWithContext { Name = key, Layout = value });
        }

        /// <summary>
        /// Parses OTLP resource attributes from <c>key1=value1,key2=value2</c> format.
        /// The <c>service.name</c> key is extracted into <see cref="ServiceName"/>.
        /// </summary>
        private void ParseOtlpResourceAttributes(string attrsStr)
        {
            foreach (var (key, value) in ParseKeyValuePairs(attrsStr))
            {
                if (string.Equals(key, "service.name", StringComparison.Ordinal))
                {
                    if (ReferenceEquals(ServiceName, _defaultServiceName) && !string.IsNullOrWhiteSpace(value))
                        ServiceName = value;
                }
                else
                {
                    ResourceAttributes.Add(new TargetPropertyWithContext { Name = key, Layout = value });
                }
            }
        }

        /// <summary>
        /// Splits a comma-separated <c>key=value</c> string, percent-decodes each token,
        /// and yields only entries with a non-empty key.
        /// </summary>
        private static IEnumerable<(string key, string value)> ParseKeyValuePairs(string input)
        {
            var pairs = input.Split(',');
            for (int i = 0; i < pairs.Length; i++)
            {
                var pair = pairs[i];
                var eqIdx = pair.IndexOf('=');
                if (eqIdx <= 0)
                    continue;
                var key = Uri.UnescapeDataString(pair.Substring(0, eqIdx).Trim());
                if (string.IsNullOrEmpty(key))
                    continue;
                var value = Uri.UnescapeDataString(pair.Substring(eqIdx + 1).Trim());
                yield return (key, value);
            }
        }

        #endregion
    }
}
