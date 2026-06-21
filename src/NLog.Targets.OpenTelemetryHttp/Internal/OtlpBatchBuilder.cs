using System;
using System.Collections.Generic;
using System.IO;

namespace NLog.Internal
{
    /// <summary>
    /// Builds an OTLP <c>ExportLogsServiceRequest</c> containing a single <c>ResourceLogs</c> entry.
    /// All log records in the batch share the same resource context (e.g., <c>service.name</c> and resource attributes).
    /// </summary>
    /// <remarks>
    /// The resulting OTLP structure is:
    /// <code>
    /// ExportLogsServiceRequest
    /// └── ResourceLogs
    ///     ├── Resource (service + attributes)
    ///     └── ScopeLogs
    ///         └── LogRecords
    /// </code>
    /// </remarks>
    internal struct OtlpBatchBuilder : IDisposable
    {
        private readonly OtlpProtobufSerializer _serializer;
        private readonly MemoryStream _stream;

        // ExportLogsServiceRequest → ResourceLogs (field 1)
        private OtlpProtobufSerializer.SubmessageWriter _resourceLogsWriter;

        // ResourceLogs → Resource (field 1)
        private OtlpProtobufSerializer.SubmessageWriter _resourceWriter;

        private OtlpProtobufSerializer.SubmessageWriter? _scopeLogsWriter;

        private bool _resourceClosed;
        private bool _disposed;

        internal OtlpBatchBuilder(
            OtlpProtobufSerializer serializer,
            MemoryStream stream)
        {
            _serializer = serializer;
            _stream = stream;

            _disposed = false;
            _resourceClosed = false;

            // ExportLogsServiceRequest.ResourceLogs
            _resourceLogsWriter = OtlpProtobufSerializer.BeginSubmessageField(stream, 1);

            // ResourceLogs.Resource
            _resourceWriter = OtlpProtobufSerializer.BeginSubmessageField(stream, 1);

            _scopeLogsWriter = null;
        }

        /// <summary>
        /// Resource attributes must be added before first log record.
        /// </summary>
        public void AddResourcePayload(KeyValuePair<byte[], byte[]> cachedResourcePayload)
        {
            if (_resourceClosed)
                throw new InvalidOperationException("Resource payload already initialized.");

            // Key = Resource payload
            _stream.Write(cachedResourcePayload.Key, 0, cachedResourcePayload.Key.Length);

            _resourceClosed = true;
            _resourceWriter.Dispose();

            // ResourceLogs.scope_logs (field 2)
            _scopeLogsWriter = OtlpProtobufSerializer.BeginSubmessageField(_stream, 2);

            // Value = ScopeLogs payload
            _stream.Write(cachedResourcePayload.Value, 0, cachedResourcePayload.Value.Length);
        }

        internal static KeyValuePair<byte[], byte[]> CreateResourcePayload(string scopeName, IEnumerable<KeyValuePair<string, string>> resourceAttributes)
        {
            // Resource payload contents
            using var resourceStream = new MemoryStream();

            foreach (var resourceAttribute in resourceAttributes)
            {
                if (string.IsNullOrEmpty(resourceAttribute.Key))
                    continue;

                OtlpProtobufSerializer.WriteKeyStringValue(
                    resourceStream,
                    1,
                    resourceAttribute.Key,
                    resourceAttribute.Value ?? string.Empty);
            }

            // ScopeLogs payload contents
            using var scopeLogsStream = new MemoryStream();

            if (!string.IsNullOrEmpty(scopeName))
            {
                // InstrumentationScope scope = 1
                using (OtlpProtobufSerializer.BeginSubmessageField(scopeLogsStream, 1))
                {
                    // InstrumentationScope.name = 1
                    OtlpProtobufSerializer.WriteStringField(
                        scopeLogsStream,
                        1,
                        scopeName);
                }
            }

            return new KeyValuePair<byte[], byte[]>(
                resourceStream.ToArray(),   // Key = Resource payload
                scopeLogsStream.ToArray()); // Value = ScopeLogs payload
        }

        /// <summary>
        /// Writes a single OTLP LogRecord.
        /// </summary>
        public void AddLogRecord<T>(LogEventInfo logEvent, string logMessage, IEnumerable<KeyValuePair<T, object?>>? properties)
        {
            if (_scopeLogsWriter is null)
                throw new InvalidOperationException("Cannot add log record before initializing scope logs.");

            // ScopeLogs.log_records (field 2)
            using (OtlpProtobufSerializer.BeginSubmessageField(_stream, 2))
            {
                _serializer.BuildLogRecord(_stream, logEvent, logMessage, properties);
            }
        }

        /// <summary>
        /// Finalizes protobuf structure.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            // Close scope logs first (if opened)
            _scopeLogsWriter?.Dispose();
            _scopeLogsWriter = null;

            // Resource already closed when scope started, but safe to ensure
            if (!_resourceClosed)
            {
                _resourceWriter.Dispose();
                _resourceClosed = true;
            }

            // Close ResourceLogs and outer request
            _resourceLogsWriter.Dispose();
        }
    }
}
