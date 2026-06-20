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

namespace NLog.Internal
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using NLog.Layouts;

    /// <summary>
    /// Serializes NLog log events into the OTLP <c>ExportLogsServiceRequest</c> protobuf binary format.
    /// </summary>
    /// <remarks>
    /// Implements manual protobuf encoding without any external proto library dependency.
    /// The output is a complete <c>ExportLogsServiceRequest</c> message as defined in the
    /// OpenTelemetry Log Data Model proto schema.
    /// <a href="https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/logs/v1/logs.proto">See OTLP logs.proto</a>
    /// </remarks>
    internal sealed class OtlpProtobufSerializer
    {
        private static readonly long UnixEpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

        /// <summary>Gets or sets the layout for capturing the W3C TraceId for each LogRecord (Hexadecimal String: 32 chars).</summary>
        public Layout<System.Diagnostics.ActivityTraceId?>? TraceId { get; set; }

        /// <summary>Gets or sets the layout for capturing the W3C SpanId for each LogRecord (Hexadecimal String: 16 chars).</summary>
        public Layout<System.Diagnostics.ActivitySpanId?>? SpanId { get; set; }

        /// <summary>
        /// Returns an <see cref="OtlpLogRecordBuilder"/> that writes a single OTLP
        /// </summary>
        public OtlpLogRecordBuilder BeginRecord(MemoryStream output)
        {
            return new OtlpLogRecordBuilder(this, output);
        }

        /// <summary>
        /// Builds a ScopeLogs protobuf message containing the instrumentation scope and a single log record.
        /// </summary>
        private void BuildScopeLogs<T>(MemoryStream stream, string scopeName, LogEventInfo logEvent, string logMessage, IEnumerable<KeyValuePair<T, object?>>? logProperties)
        {
            // ScopeLogs { InstrumentationScope scope = 1; repeated LogRecord log_records = 2 }
            if (!string.IsNullOrEmpty(scopeName))
            {
                // InstrumentationScope { string name = 1; string version = 2 }
                var scopeNameMaxBytes = Encoding.UTF8.GetMaxByteCount(scopeName.Length);
                using (BeginSubmessageField(stream, 1, scopeNameMaxBytes))
                {
                    WriteStringField(stream, 1, scopeName, scopeNameMaxBytes);
                }
            }

            using (BeginSubmessageField(stream, 2))
            {
                BuildLogRecord(stream, logEvent, logMessage, logProperties);
            }
        }

        /// <summary>
        /// Builds a LogRecord protobuf message for a single log event.
        /// </summary>
        private void BuildLogRecord<T>(MemoryStream stream, LogEventInfo logEvent, string logMessage, IEnumerable<KeyValuePair<T, object?>>? logProperties)
        {
            // LogRecord proto field numbers:
            //   fixed64 time_unix_nano = 1
            //   SeverityNumber severity_number = 2
            //   string severity_text = 3
            //   AnyValue body = 5
            //   repeated KeyValue attributes = 6
            //   bytes trace_id = 9
            //   bytes span_id = 10
            var unixNano = ToUnixNano(logEvent.TimeStamp);
            WriteFixed64Field(stream, 1, unixNano);

            var severityNumber = MapSeverityNumber(logEvent.Level);
            if (severityNumber != 0)
            {
                WriteVarintField(stream, 2, (ulong)severityNumber);
                WriteStringField(stream, 3, logEvent.Level.ToString());
            }

            // body = AnyValue { string string_value = 1 }
            if (!string.IsNullOrEmpty(logMessage))
            {
                BuildAnyValueString(stream, 5, logMessage);
            }

            if (!string.IsNullOrEmpty(logEvent.LoggerName))
            {
                WriteKeyStringValue(stream, 6, "LoggerName", logEvent.LoggerName);
            }

            if (logEvent.Exception != null)
            {
                WriteKeyStringValue(stream, 6, "exception.type", logEvent.Exception.GetType().ToString());
                WriteKeyStringValue(stream, 6, "exception.message", logEvent.Exception.Message);
                WriteKeyStringValue(stream, 6, "exception.stacktrace", logEvent.Exception.ToString());
            }

            if (logProperties != null)
            {
                var enumerator = logProperties.GetEnumerator();
                try
                {
                    while (enumerator.MoveNext())
                    {
                        var prop = enumerator.Current;
                        var key = prop.Key?.ToString();
                        if (key is null || string.IsNullOrEmpty(key))
                            continue;

                        WriteKeyValue(stream, 6, key, prop.Value);
                    }
                }
                finally
                {
                    (enumerator as IDisposable)?.Dispose();
                }
            }

            // trace_id (field 9) and span_id (field 10)
            var traceId = TraceId?.RenderValue(logEvent);
            if (traceId.HasValue)
            {
                WriteTraceIdField(stream, 9, traceId.Value);
            }
            var spanId = SpanId?.RenderValue(logEvent);
            if (spanId.HasValue)
            {
                WriteSpanIdField(stream, 10, spanId.Value);
            }
        }

        /// <summary>
        /// Builder for incrementally constructing a single OTLP ResourceLogs entry.
        /// Obtain via <see cref="OtlpProtobufSerializer.BeginRecord"/>; dispose to finalize.
        /// </summary>
        internal struct OtlpLogRecordBuilder : IDisposable
        {
            private readonly OtlpProtobufSerializer _serializer;
            private readonly MemoryStream _stream;
            private readonly SubmessageWriter _requestWriter;
            private readonly SubmessageWriter _resourceWriter;
            private bool _completed;

            internal OtlpLogRecordBuilder(OtlpProtobufSerializer serializer, MemoryStream stream)
            {
                _serializer = serializer;
                _stream = stream;
                _completed = false;

                // ExportLogsServiceRequest { repeated ResourceLogs resource_logs = 1 }
                _requestWriter = BeginSubmessageField(stream, 1);
                // ResourceLogs { Resource resource = 1; ... }
                _resourceWriter = BeginSubmessageField(stream, 1);
            }

            /// <summary>Writes a resource attribute KeyValue into the open Resource submessage.</summary>
            public void AddResourceAttribute(string attributeName, string attributeValue)
            {
                WriteKeyStringValue(_stream, 1, attributeName, attributeValue);
            }

            /// <summary>Closes the Resource submessage, writes ScopeLogs, and finalizes the OTLP message.</summary>
            public void AddScopeLogs<T>(string scopeName, LogEventInfo logEvent, string logMessage, IEnumerable<KeyValuePair<T, object?>>? logProperties = null)
            {
                if (_completed) return;
                _completed = true;

                _resourceWriter.Dispose();

                // ResourceLogs { ... repeated ScopeLogs scope_logs = 2 }
                using (BeginSubmessageField(_stream, 2))
                {
                    _serializer.BuildScopeLogs(_stream, scopeName, logEvent, logMessage, logProperties);
                }

                _requestWriter.Dispose();
            }

            public void Complete()
            {
                if (_completed) return;
                _completed = true;
                _resourceWriter.Dispose();
                _requestWriter.Dispose();
            }

            /// <inheritdoc cref="Complete"/>
            public void Dispose() => Complete();
        }

        private static void BuildAnyValueString(MemoryStream stream, int fieldNumber, string value)
        {
            var maxByteCount = Encoding.UTF8.GetMaxByteCount(value.Length);
            BuildAnyValueString(stream, fieldNumber, value, maxByteCount);
        }

        private static void BuildAnyValueString(MemoryStream stream, int fieldNumber, string value, int maxByteCount)
        {
            if (string.IsNullOrEmpty(value))
                return;

            using (BeginSubmessageField(stream, fieldNumber, maxByteCount))
            {
                WriteStringField(stream, 1, value, maxByteCount);
            }
        }

#if NET8_0_OR_GREATER
        /// <summary>
        /// Formats <paramref name="value"/> into a stack-allocated char buffer via <see cref="ISpanFormattable.TryFormat"/>,
        /// then encodes the result as UTF-8 directly into <paramref name="stream"/> — no intermediate string allocation.
        /// Falls back to a string allocation when the value is too wide for the stack buffer.
        /// Using a generic constraint avoids boxing value-type implementations (e.g. DateTime, DateTimeOffset, Guid).
        /// </summary>
        private static void BuildAnyValueSpanFormattable<T>(MemoryStream stream, int fieldNumber, T value, string? format) where T : ISpanFormattable
        {
            const int StackCharBufferSize = 128;
            Span<char> charBuf = stackalloc char[StackCharBufferSize];
            if (value.TryFormat(charBuf, out int charsWritten, format, System.Globalization.CultureInfo.InvariantCulture))
            {
                var formatted = charBuf.Slice(0, charsWritten);
                var maxByteCount = Encoding.UTF8.GetMaxByteCount(charsWritten);
                using (BeginSubmessageField(stream, fieldNumber, maxByteCount))
                {
                    WriteStringFieldSpan(stream, 1, formatted, maxByteCount);
                }
            }
            else
            {
                BuildAnyValueString(stream, fieldNumber, value.ToString(format, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
            }
        }
#endif

        internal static void BuildAnyValue(MemoryStream stream, int fieldNumber, object? value)
        {
            // AnyValue { string string_value = 1; bool bool_value = 2; int64 int_value = 3; double double_value = 4; ArrayValue array_value = 5; KeyValueList kvlist_value = 6 }
            if (value is Enum)
            {
                BuildAnyValueString(stream, fieldNumber, value?.ToString() ?? string.Empty);
                return;
            }

            if (value is IConvertible convertible)
            {
                switch (convertible.GetTypeCode())
                {
                    case TypeCode.Boolean:
                        // bool_value field: tag(1) + varint(1) = 2 bytes
                        using (BeginSubmessageField(stream, fieldNumber, 2))
                        {
                            WriteVarintField(stream, 2, convertible.ToBoolean(System.Globalization.CultureInfo.InvariantCulture) ? 1UL : 0UL);
                        }
                        return;
                    case TypeCode.SByte:
                    case TypeCode.Int16:
                    case TypeCode.Int32:
                    case TypeCode.Int64:
                        // int_value field: negative values sign-extend to 10 varint bytes: tag(1) + 10 = 11 bytes
                        var varInt = unchecked((ulong)convertible.ToInt64(System.Globalization.CultureInfo.InvariantCulture));
                        using (BeginSubmessageField(stream, fieldNumber, 11))
                        {
                            WriteVarintField(stream, 3, varInt);
                        }
                        return;
                    case TypeCode.Byte:
                    case TypeCode.UInt16:
                    case TypeCode.UInt32:
                    case TypeCode.UInt64:
                        // int_value field: max ulong → 10 varint bytes: tag(1) + 10 = 11 bytes
                        var varUInt = convertible.ToUInt64(System.Globalization.CultureInfo.InvariantCulture);
                        using (BeginSubmessageField(stream, fieldNumber, 11))
                        {
                            WriteVarintField(stream, 3, varUInt);
                        }
                        return;
                    case TypeCode.Single:
                    case TypeCode.Double:
                    case TypeCode.Decimal:
                        // double_value field: fixed64 → tag(1) + 8 bytes = 9 bytes
                        var doubleVal = convertible.ToDouble(System.Globalization.CultureInfo.InvariantCulture);
                        using (BeginSubmessageField(stream, fieldNumber, 9))
                        {
                            WriteFixed64Field(stream, 4, unchecked((ulong)BitConverter.DoubleToInt64Bits(doubleVal)));
                        }
                        return;
                    case TypeCode.DateTime:
#if NET8_0_OR_GREATER
                        BuildAnyValueSpanFormattable(stream, fieldNumber, convertible.ToDateTime(System.Globalization.CultureInfo.InvariantCulture), "o");
#else
                        BuildAnyValueString(stream, fieldNumber, convertible.ToDateTime(System.Globalization.CultureInfo.InvariantCulture).ToString("o", System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
#endif
                        return;
                    default:
                        BuildAnyValueString(stream, fieldNumber, convertible.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
                        return;
                }
            }

            if (value is DateTimeOffset dateTimeOffset)
            {
#if NET8_0_OR_GREATER
                BuildAnyValueSpanFormattable(stream, fieldNumber, dateTimeOffset, "o");
#else
                BuildAnyValueString(stream, fieldNumber, dateTimeOffset.ToString("o", System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
#endif
                return;
            }

#if NET8_0_OR_GREATER
            if (value is ISpanFormattable spanFormattable)
            {
                BuildAnyValueSpanFormattable(stream, fieldNumber, spanFormattable, format: null);
                return;
            }
#endif

            if (value is IFormattable formattable)
            {
                BuildAnyValueString(stream, fieldNumber, formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
                return;
            }

            if (value is IList list)
            {
                using (BeginSubmessageField(stream, fieldNumber))
                {
                    BuildAnyValueArray(stream, list);
                }
                return;
            }

            if (value is IDictionary dict)
            {
                using (BeginSubmessageField(stream, fieldNumber))
                {
                    BuildAnyValueKvList(stream, dict);
                }
                return;
            }

            if (value is IEnumerable enumerable)
            {
                using (BeginSubmessageField(stream, fieldNumber))
                {
                    BuildAnyValueArray(stream, enumerable);
                }
                return;
            }

            BuildAnyValueString(stream, fieldNumber, value?.ToString() ?? string.Empty);
        }

        private static void BuildAnyValueKvList(MemoryStream stream, IDictionary dict)
        {
            // AnyValue { KeyValueList kvlist_value = 6 }
            // KeyValueList { repeated KeyValue values = 1 }
            using (BeginSubmessageField(stream, 6))
            {
                var enumerator = dict.GetEnumerator();
                try
                {
                    while (enumerator.MoveNext())
                    {
                        var key = enumerator.Key?.ToString();
                        if (key is null || string.IsNullOrEmpty(key))
                            continue;

                        WriteKeyValue(stream, 1, key, enumerator.Value);
                    }
                }
                finally
                {
                    (enumerator as IDisposable)?.Dispose();
                }
            }
        }

        private static void BuildAnyValueArray(MemoryStream stream, IList list)
        {
            // AnyValue { ArrayValue array_value = 5 }
            // ArrayValue { repeated AnyValue values = 1 }
            using (BeginSubmessageField(stream, 5))
            {
                for (int i = 0; i < list.Count; i++)
                {
                    BuildAnyValue(stream, 1, list[i]);
                }
            }
        }

        private static void BuildAnyValueArray(MemoryStream stream, IEnumerable enumerable)
        {
            // AnyValue { ArrayValue array_value = 5 }
            // ArrayValue { repeated AnyValue values = 1 }
            using (BeginSubmessageField(stream, 5))
            {
                var enumerator = enumerable.GetEnumerator();
                try
                {
                    while (enumerator.MoveNext())
                    {
                        BuildAnyValue(stream, 1, enumerator.Current);
                    }
                }
                finally
                {
                    (enumerator as IDisposable)?.Dispose();
                }
            }
        }

        private static void WriteKeyStringValue(MemoryStream parent, int fieldNumber, string key, string value)
        {
            // KeyValue { string key = 1; AnyValue value = 2 }
            var keyMaxBytes = Encoding.UTF8.GetMaxByteCount(key.Length);
            var valueMaxBytes = Encoding.UTF8.GetMaxByteCount(value.Length);
            // +16 accounts for field tags and inner length-prefix bytes of the key string field and AnyValue wrapper
            using (BeginSubmessageField(parent, fieldNumber, keyMaxBytes + valueMaxBytes + 16))
            {
                WriteStringField(parent, 1, key, keyMaxBytes);
                BuildAnyValueString(parent, 2, value, valueMaxBytes);
            }
        }

        private static void WriteKeyValue(MemoryStream parent, int fieldNumber, string key, object? value)
        {
            if (value is string stringValue)
            {
                WriteKeyStringValue(parent, fieldNumber, key, stringValue);
            }
            else
            {
                // KeyValue { string key = 1; AnyValue value = 2 }
                var keyMaxBytes = Encoding.UTF8.GetMaxByteCount(key.Length);
                // key string field: tag(1)+length(up to 2)+keyMaxBytes; AnyValue wrapper: tag(1)+length(1); largest scalar (int64/uint64): tag(1)+10 varint bytes
                var maxByteCount = value is IConvertible ? keyMaxBytes + 16 : int.MaxValue;
                using (BeginSubmessageField(parent, fieldNumber, maxByteCount))
                {
                    WriteStringField(parent, 1, key, keyMaxBytes);
                    BuildAnyValue(parent, 2, value);
                }
            }
        }

        private static void WriteVarint(MemoryStream stream, ulong value)
        {
            while (value > 0x7F)
            {
                stream.WriteByte((byte)((value & 0x7F) | 0x80));
                value >>= 7;
            }
            stream.WriteByte((byte)value);
        }

        private static void WriteTag(MemoryStream stream, int fieldNumber, int wireType)
        {
            WriteVarint(stream, (ulong)((fieldNumber << 3) | wireType));
        }

        private static void WriteVarintField(MemoryStream stream, int fieldNumber, ulong value)
        {
            WriteTag(stream, fieldNumber, 0);
            WriteVarint(stream, value);
        }

        private static void WriteFixed64Field(MemoryStream stream, int fieldNumber, ulong value)
        {
            WriteTag(stream, fieldNumber, 1);
#if NET || NETSTANDARD2_1_OR_GREATER
            var pos = (int)stream.Position;
            stream.SetLength(pos + 8);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(stream.GetBuffer().AsSpan(pos, 8), value);
            stream.Position = pos + 8;
#else
            for (int i = 0; i < 8; i++)
            {
                stream.WriteByte((byte)(value & 0xFF));
                value >>= 8;
            }
#endif
        }

        private static void WriteStringField(MemoryStream stream, int fieldNumber, string value)
        {
            WriteStringField(stream, fieldNumber, value, Encoding.UTF8.GetMaxByteCount(value.Length));
        }

        private static void WriteStringField(MemoryStream stream, int fieldNumber, string value, int maxByteCount)
        {
#if NET || NETSTANDARD2_1_OR_GREATER
            WriteStringFieldSpan(stream, fieldNumber, value.AsSpan(), maxByteCount);
#else
            if (maxByteCount >= SubmessageWriter.MaxContentLength)
                throw new InvalidOperationException($"String field {fieldNumber} is too large ({maxByteCount} bytes exceeds the {SubmessageWriter.MaxContentLength}-byte protobuf limit).");

            // 1-byte length for short strings (≤127 bytes), 2-byte padded varint for medium, 4-byte for large.
            // actualByteCount <= maxByteCount so the selected size always fits.
            var varintSize = maxByteCount > SubmessageWriter.MaxContent2ByteThreshold ? 4 : (maxByteCount > 127 ? 2 : 1);
            WriteTag(stream, fieldNumber, 2);
            var varintPos = (int)stream.Position;
            var contentStart = varintPos + varintSize;
            stream.SetLength(contentStart + maxByteCount);
            var buf = stream.GetBuffer();
            var length = Encoding.UTF8.GetBytes(value, 0, value.Length, buf, contentStart);
            if (varintSize == 1)
            {
                buf[varintPos] = (byte)length;
            }
            else if (varintSize == 2)
            {
                buf[varintPos] = (byte)((length & 0x7F) | 0x80);
                buf[varintPos + 1] = (byte)(length >> 7);
            }
            else
            {
                buf[varintPos] = (byte)((length & 0x7F) | 0x80);
                buf[varintPos + 1] = (byte)(((length >> 7) & 0x7F) | 0x80);
                buf[varintPos + 2] = (byte)(((length >> 14) & 0x7F) | 0x80);
                buf[varintPos + 3] = (byte)(length >> 21);
            }
            stream.SetLength(contentStart + length);
            stream.Position = contentStart + length;
#endif
        }

#if NET || NETSTANDARD2_1_OR_GREATER
        private static void WriteStringFieldSpan(MemoryStream stream, int fieldNumber, ReadOnlySpan<char> value, int maxByteCount)
        {
            if (maxByteCount >= SubmessageWriter.MaxContentLength)
                throw new InvalidOperationException($"String field {fieldNumber} is too large ({maxByteCount} bytes exceeds the {SubmessageWriter.MaxContentLength}-byte protobuf limit).");

            // 1-byte length for short strings (≤127 bytes), 2-byte padded varint for medium, 4-byte for large.
            // actualByteCount <= maxByteCount so the selected size always fits.
            var varintSize = maxByteCount > SubmessageWriter.MaxContent2ByteThreshold ? 4 : (maxByteCount > 127 ? 2 : 1);
            WriteTag(stream, fieldNumber, 2);
            var varintPos = (int)stream.Position;
            var contentStart = varintPos + varintSize;
            stream.SetLength(contentStart + maxByteCount);
            var buf = stream.GetBuffer();
            var length = Encoding.UTF8.GetBytes(value, buf.AsSpan(contentStart));
            if (varintSize == 1)
            {
                buf[varintPos] = (byte)length;
            }
            else if (varintSize == 2)
            {
                buf[varintPos] = (byte)((length & 0x7F) | 0x80);
                buf[varintPos + 1] = (byte)(length >> 7);
            }
            else
            {
                buf[varintPos] = (byte)((length & 0x7F) | 0x80);
                buf[varintPos + 1] = (byte)(((length >> 7) & 0x7F) | 0x80);
                buf[varintPos + 2] = (byte)(((length >> 14) & 0x7F) | 0x80);
                buf[varintPos + 3] = (byte)(length >> 21);
            }
            stream.SetLength(contentStart + length);
            stream.Position = contentStart + length;
        }
#endif

        private static SubmessageWriter BeginSubmessageField(MemoryStream stream, int fieldNumber, int maxByteCount = int.MaxValue)
        {
            return new SubmessageWriter(stream, fieldNumber, maxByteCount);
        }

        private readonly struct SubmessageWriter : IDisposable
        {
            // Protobuf allows non-minimal (padded) varints — decoders must accept them.
            // fixedLength=false reserves 2 bytes (up to 16,383 bytes content) for small leaf nodes.
            // fixedLength=true  reserves 4 bytes (up to ~256 MB content) for large containers.
            internal const int MaxContentLength = (1 << 28) - 1;
            internal const int MaxContent2ByteLength = (1 << 14) - 1; // 16,383 bytes — the true 2-byte padded varint limit
            internal const int MaxContent2ByteThreshold = MaxContent2ByteLength - 16; // Safety margin for tag + length-prefix overhead of nested fields

            private readonly MemoryStream _stream;
            private readonly ulong _tagValue;
            private readonly int _headerPos;
            private readonly int _tagSize;
            private readonly int _paddedLengthSize;

            internal SubmessageWriter(MemoryStream stream, int fieldNumber, int maxByteCount)
            {
                _tagValue = (ulong)((fieldNumber << 3) | 2);
                _tagSize = _tagValue < 0x80 ? 1 : 2; // field 1-15 = 1 byte tag; field 16+ = 2 bytes
                _stream = stream;
                _headerPos = (int)stream.Position;
                _paddedLengthSize = maxByteCount <= 127 ? 1 : (maxByteCount <= MaxContent2ByteThreshold ? 2 : 4);
                stream.Position = _headerPos + _tagSize + _paddedLengthSize;
            }

            public void Dispose()
            {
                var endPos = (int)_stream.Position;
                var contentLength = endPos - _headerPos - _tagSize - _paddedLengthSize;
                if (contentLength <= 0)
                {
                    _stream.Position = _headerPos;
                    _stream.SetLength(_headerPos);
                    return;
                }

                WriteHeader(contentLength);
            }

            private void WriteHeader(int contentLength)
            {
#if NET || NETSTANDARD2_1_OR_GREATER
                var header = _stream.GetBuffer().AsSpan(_headerPos);
                WriteTagToBuffer(header, _tagValue, 0);
                header = header.Slice(_tagSize, _paddedLengthSize);
                const int offset = 0;
#else
                var header = _stream.GetBuffer();
                WriteTagToBuffer(header, _tagValue, _headerPos);
                int offset = _headerPos + _tagSize;
#endif
                if (_paddedLengthSize == 1)
                {
                    if (contentLength > 127)
                        throw new InvalidOperationException($"Protobuf content length {contentLength} exceeds the 1-byte varint limit of 127 bytes.");

                    header[offset] = (byte)contentLength;
                }
                else if (_paddedLengthSize == 2)
                {
                    if (contentLength > MaxContent2ByteLength)
                        throw new InvalidOperationException($"Protobuf content length {contentLength} exceeds the 2-byte padded varint limit of {MaxContent2ByteLength} bytes.");

                    // Encode as exactly 2 varint bytes (padded) — valid per the protobuf spec
                    header[offset] = (byte)((contentLength & 0x7F) | 0x80);
                    header[offset + 1] = (byte)(contentLength >> 7);
                }
                else
                {
                    if (contentLength >= MaxContentLength)
                        throw new InvalidOperationException($"Protobuf content length {contentLength} exceeds the 4-byte padded varint limit of {MaxContentLength} bytes.");

                    // Encode as exactly 4 varint bytes (padded) — valid per the protobuf spec
                    header[offset] = (byte)((contentLength & 0x7F) | 0x80);
                    header[offset + 1] = (byte)(((contentLength >> 7) & 0x7F) | 0x80);
                    header[offset + 2] = (byte)(((contentLength >> 14) & 0x7F) | 0x80);
                    header[offset + 3] = (byte)(contentLength >> 21);
                }
            }

#if NET || NETSTANDARD2_1_OR_GREATER
            private static void WriteTagToBuffer(Span<byte> buffer, ulong value, int offset)
#else
            private static void WriteTagToBuffer(byte[] buffer, ulong value, int offset)
#endif
            {
                while (value > 0x7F)
                {
                    buffer[offset++] = (byte)((value & 0x7F) | 0x80);
                    value >>= 7;
                }
                buffer[offset] = (byte)value;
            }
        }

        private static void WriteTraceIdField(MemoryStream stream, int fieldNumber, System.Diagnostics.ActivityTraceId traceId)
        {
            if (traceId == default)
                return;

            WriteTag(stream, fieldNumber, 2);
            WriteVarint(stream, 16); // TraceId = 16 bytes

            var pos = (int)stream.Position;
            stream.SetLength(pos + 16);

            traceId.CopyTo(stream.GetBuffer().AsSpan(pos, 16));

            stream.Position = pos + 16;
        }

        private static void WriteSpanIdField(MemoryStream stream, int fieldNumber, System.Diagnostics.ActivitySpanId spanId)
        {
            if (spanId == default)
                return;

            WriteTag(stream, fieldNumber, 2);
            WriteVarint(stream, 8); // SpanId = 8 bytes

            var pos = (int)stream.Position;
            stream.SetLength(pos + 8);

            spanId.CopyTo(stream.GetBuffer().AsSpan(pos, 8));

            stream.Position = pos + 8;
        }

        internal static ulong ToUnixNano(DateTime timestamp)
        {
            var utcTicks = timestamp.ToUniversalTime().Ticks - UnixEpochTicks;
            return utcTicks > 0 ? (ulong)utcTicks * 100UL : 0UL;
        }

        internal static int MapSeverityNumber(LogLevel? level)
        {
            if (level == LogLevel.Trace) return 1;   // SEVERITY_NUMBER_TRACE
            if (level == LogLevel.Debug) return 5;   // SEVERITY_NUMBER_DEBUG
            if (level == LogLevel.Info) return 9;    // SEVERITY_NUMBER_INFO
            if (level == LogLevel.Warn) return 13;   // SEVERITY_NUMBER_WARN
            if (level == LogLevel.Error) return 17;  // SEVERITY_NUMBER_ERROR
            if (level == LogLevel.Fatal) return 21;  // SEVERITY_NUMBER_FATAL
            return 0;
        }
    }
}
