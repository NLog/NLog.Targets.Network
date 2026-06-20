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
        public void AddResourceAttribute(string name, string value)
        {
            if (_resourceClosed)
                throw new InvalidOperationException("Cannot add resource attributes after first log record.");

            OtlpProtobufSerializer.WriteKeyStringValue(_stream, 1, name, value);
        }

        /// <summary>
        /// Ensures ScopeLogs exists (created lazily on first log record).
        /// </summary>
        private void EnsureScopeLogs(string scopeName)
        {
            if (_scopeLogsWriter != null)
                return;

            // Close resource section BEFORE entering scope_logs
            _resourceClosed = true;
            _resourceWriter.Dispose();

            // ResourceLogs.scope_logs (field 2)
            _scopeLogsWriter = OtlpProtobufSerializer.BeginSubmessageField(_stream, 2);

            // ScopeLogs.scope (field 1)
            if (!string.IsNullOrEmpty(scopeName))
            {
                using (OtlpProtobufSerializer.BeginSubmessageField(_stream, 1))
                {
                    OtlpProtobufSerializer.WriteStringField(_stream, 1, scopeName);
                }
            }
        }

        /// <summary>
        /// Writes a single OTLP LogRecord.
        /// </summary>
        public void AddLogRecord<T>(string scopeName, LogEventInfo logEvent, string logMessage, IEnumerable<KeyValuePair<T, object?>>? properties)
        {
            EnsureScopeLogs(scopeName);

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
