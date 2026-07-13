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
    using NLog.Config;
    using NLog.Internal;
    using NLog.Layouts;

    /// <summary>
    /// Sends log events to OpenTelemetry HTTP endpoint using protobuf (OTLP/HTTP).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The target serializes log events into the OTLP ExportLogsServiceRequest protobuf format
    /// and sends them via HTTP POST. Typical endpoint URL is <c>http://localhost:4318/v1/logs</c>.
    /// </para>
    /// </remarks>
    [Target("OpenTelemetry")]
    [Target("OpenTelemetryHttp")]
    public class OpenTelemetryHttpTarget : HttpClientTarget
    {
        private static readonly SimpleLayout _defaultServiceName = new SimpleLayout("${appdomain:format=Friendly}");
        private static readonly SimpleLayout _defaultServiceVersion = new SimpleLayout("${assembly-version:Default=}");
        private static readonly SimpleLayout _defaultHostName = new SimpleLayout("${hostname}");
        private static readonly Layout _defaultOperatingSystem = Layout.FromMethod(static evt => ResolveOperatingSystem(), LayoutRenderOptions.ThreadAgnostic);

        private static readonly string EmptyTraceIdToHexString = default(System.Diagnostics.ActivityTraceId).ToHexString();
        private static readonly string EmptySpanIdToHexString = default(System.Diagnostics.ActivitySpanId).ToHexString();

        private OtlpProtobufSerializer _serializer = new OtlpProtobufSerializer();
        private KeyValuePair<byte[], byte[]> _cachedResourcePayload;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenTelemetryHttpTarget"/> class.
        /// </summary>
        public OpenTelemetryHttpTarget()
        {
            ContentType = "application/x-protobuf"; // application/json not supported, only protobuf as OTLP_PROTOCOL
            BatchSize = 200;                // Consider doubling this if enabling compression
            TaskDelayMilliseconds = 50;     // Small delay to improve chance of batching and reducing number of HTTP requests.
            RetryDelayMilliseconds = 2500;  // Notice OTel SDK initial backoff is 5 secs
            RetryCount = 3;                 // Notice OTel SDK default max 5 retries
            Layout = "${message}";
            IncludeEventProperties = true;
        }

        /// <summary>
        /// Gets or sets the OTLP resource <c>service.name</c> attribute value.
        /// </summary>
        /// <remarks>Default: <c>${appdomain:format=Friendly}</c>. Defaults to <c>Unknown</c> when empty value</remarks>
        public Layout ServiceName { get; set; } = _defaultServiceName;

        /// <summary>
        /// Gets or sets the OTLP resource <c>service.version</c> attribute value.
        /// </summary>
        /// <remarks>Default: <c>${assembly-version:Default=}</c>.</remarks>
        public Layout ServiceVersion { get; set; } = _defaultServiceVersion;

        /// <summary>
        /// Gets or sets the OTLP resource <c>host.name</c> attribute value.
        /// </summary>
        /// <remarks>Default: <c>${hostname}</c>.</remarks>
        public Layout HostName { get; set; } = _defaultHostName;

        /// <summary>
        /// Gets or sets the OpenTelemetry instrumentation scope name.
        /// </summary>
        /// <remarks>Default: <see langword="NLog"/></remarks>
        public string ScopeName { get; set; } = "NLog";

        /// <summary>
        /// Gets or sets additional OpenTelemetry resource attributes.
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
            _cachedResourcePayload = default;
            base.InitializeTarget();
        }

        /// <inheritdoc />
        protected override int SerializePayload(IList<LogEventInfo> logEvents, MemoryStream output)
        {
            if (_cachedResourcePayload.Key is null)
            {
                var firstEvent = logEvents.Count > 0 ? logEvents[0] : LogEventInfo.CreateNullEvent();
                _cachedResourcePayload = OtlpBatchBuilder.CreateResourcePayload(
                    ScopeName,
                    GetResourceAttributes(firstEvent));
            }

            using (var batch = _serializer.BeginBatch(output))
            {
                batch.AddResourcePayload(_cachedResourcePayload);

                for (int i = 0; i < logEvents.Count; i++)
                {
                    var logEvent = logEvents[i];

                    var logMessage = RenderLogEvent(Layout, logEvent);
                    var properties = GetLogEventProperties(logEvent);
                    if (properties is null && (IncludeEventProperties && logEvent.HasProperties))
                    {
                        batch.AddLogRecord(logEvent, logMessage, logEvent.Properties);
                    }
                    else
                    {
                        batch.AddLogRecord(logEvent, logMessage, properties);
                    }

                    if (output.Length >= MaxPayloadSizeBytes)
                        return i + 1;   // consumed and included this LogEvent
                }
            }

            return logEvents.Count;
        }

        private IEnumerable<KeyValuePair<string, object?>>? GetLogEventProperties(LogEventInfo logEvent)
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

        private IEnumerable<KeyValuePair<string, object>> GetResourceAttributes(LogEventInfo firstEvent)
        {
            Layout? serviceNameLayout = ServiceName;
            Layout? serviceVersionLayout = ServiceVersion;
            Layout? hostNameLayout = HostName;
            Layout? operatingSystemLayout = _defaultOperatingSystem;
            int? processId =
#if NET
                Environment.ProcessId;
#else
                System.Diagnostics.Process.GetCurrentProcess().Id;
#endif
            string telemetrySdkLanguage = "dotnet";
            string telemetrySdkName = "NLog.OTLP.HTTP";
            string telemetrySdkVersion = typeof(OpenTelemetryHttpTarget).Assembly.GetName().Version?.ToString() ?? string.Empty;

            for (int j = 0; j < ResourceAttributes.Count; ++j)
            {
                var attr = ResourceAttributes[j];
                if (string.IsNullOrWhiteSpace(attr.Name))
                    continue;

                var stringValue = RenderLogEvent(attr.Layout, firstEvent);
                if (!attr.IncludeEmptyValue && string.IsNullOrWhiteSpace(stringValue))
                    continue;

                object value = stringValue;

                if (attr.Name == "service.name")
                    serviceNameLayout = null;
                else if (attr.Name == "service.version")
                    serviceVersionLayout = null;
                else if (attr.Name == "process.id")
                {
                    processId = null;
                    if (long.TryParse(stringValue, out var parsedProcessId))
                        value = parsedProcessId;
                }
                else if (attr.Name == "host.name")
                    hostNameLayout = null;
                else if (attr.Name == "os.type")
                    operatingSystemLayout = null;
                else if (attr.Name == "telemetry.sdk.language")
                    telemetrySdkLanguage = string.Empty;
                else if (attr.Name == "telemetry.sdk.name")
                    telemetrySdkName = string.Empty;
                else if (attr.Name == "telemetry.sdk.version")
                    telemetrySdkVersion = string.Empty;

                yield return new KeyValuePair<string, object>(attr.Name, value);
            }

            if (serviceNameLayout != null)
            {
                var serviceName = RenderLogEvent(serviceNameLayout, firstEvent);
                if (string.IsNullOrEmpty(serviceName))
                    serviceName = "Unknown";
                yield return new KeyValuePair<string, object>("service.name", serviceName);
            }
            if (serviceVersionLayout != null)
            {
                var serviceVersion = RenderLogEvent(serviceVersionLayout, firstEvent);
                if (!string.IsNullOrEmpty(serviceVersion))
                    yield return new KeyValuePair<string, object>("service.version", serviceVersion);
            }
            if (processId.HasValue)
            {
                yield return new KeyValuePair<string, object>("process.id", processId.Value);
            }
            if (hostNameLayout != null)
            {
                var hostName = RenderLogEvent(hostNameLayout, firstEvent);
                if (!string.IsNullOrEmpty(hostName))
                    yield return new KeyValuePair<string, object>("host.name", hostName);
            }
            if (operatingSystemLayout != null)
            {
                var operatingSystem = RenderLogEvent(operatingSystemLayout, firstEvent);
                if (!string.IsNullOrEmpty(operatingSystem))
                    yield return new KeyValuePair<string, object>("os.type", operatingSystem);
            }
            if (!string.IsNullOrEmpty(telemetrySdkLanguage))
                yield return new KeyValuePair<string, object>("telemetry.sdk.language", telemetrySdkLanguage);
            if (!string.IsNullOrEmpty(telemetrySdkName))
                yield return new KeyValuePair<string, object>("telemetry.sdk.name", telemetrySdkName);
            if (!string.IsNullOrEmpty(telemetrySdkVersion))
                yield return new KeyValuePair<string, object>("telemetry.sdk.version", telemetrySdkVersion);
        }

        private static string ResolveOperatingSystem()
        {
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                return "windows";
            else if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux))
                return "linux";
            else if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
                return "osx";
            else if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Create("ANDROID")))
                return "android";
            else
                return "other";
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
                    SendTimeoutSeconds = (int)Math.Ceiling(timeoutMs / 1000.0);
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
                else if (string.Equals(key, "service.version", StringComparison.Ordinal))
                {
                    if (ReferenceEquals(ServiceVersion, _defaultServiceVersion) && !string.IsNullOrWhiteSpace(value))
                        ServiceVersion = value;
                }
                else if (string.Equals(key, "host.name", StringComparison.Ordinal))
                {
                    if (ReferenceEquals(HostName, _defaultHostName) && !string.IsNullOrWhiteSpace(value))
                        HostName = value;
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
