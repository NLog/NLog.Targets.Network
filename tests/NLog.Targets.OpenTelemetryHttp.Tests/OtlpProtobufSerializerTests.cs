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

namespace NLog.Targets.HttpOTLP.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using NLog.Internal;
    using Xunit;

    /// <summary>
    /// Unit tests for <see cref="OtlpProtobufSerializer"/> that validate protobuf output
    /// against the OpenTelemetry OTLP logs.proto specification without requiring an HTTP server.
    /// </summary>
    /// <remarks>
    /// Proto field references:
    ///   ExportLogsServiceRequest { repeated ResourceLogs resource_logs = 1 }
    ///   ResourceLogs { Resource resource = 1; repeated ScopeLogs scope_logs = 2 }
    ///   Resource { repeated KeyValue attributes = 1 }
    ///   ScopeLogs { InstrumentationScope scope = 1; repeated LogRecord log_records = 2 }
    ///   InstrumentationScope { string name = 1 }
    ///   LogRecord { fixed64 time_unix_nano = 1; SeverityNumber severity_number = 2; string severity_text = 3;
    ///               AnyValue body = 5; repeated KeyValue attributes = 6; bytes trace_id = 9; bytes span_id = 10 }
    ///   AnyValue { string string_value = 1; bool bool_value = 2; int64 int_value = 3; double double_value = 4;
    ///              ArrayValue array_value = 5; KeyValueList kvlist_value = 6 }
    ///   KeyValue { string key = 1; AnyValue value = 2 }
    ///   ArrayValue { repeated AnyValue values = 1 }
    ///   KeyValueList { repeated KeyValue values = 1 }
    /// </remarks>
    public class OtlpProtobufSerializerTests
    {
        #region Structure tests

        [Fact]
        public void Serialize_ProducesValidExportLogsServiceRequest_TopLevelStructure()
        {
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "hello"));

            // Top-level message: ExportLogsServiceRequest { repeated ResourceLogs resource_logs = 1 }
            var topFields = ReadProtobufFields(output);
            Assert.Single(topFields);
            var resourceLogsField = topFields[0];
            Assert.Equal(1, resourceLogsField.FieldNumber);  // resource_logs field
            Assert.Equal(2, resourceLogsField.WireType);     // length-delimited

            // ResourceLogs { Resource resource = 1; repeated ScopeLogs scope_logs = 2 }
            var rlFields = ReadProtobufFields(resourceLogsField.Data);
            Assert.Single(rlFields);
            Assert.Equal(2, rlFields[0].FieldNumber); // scope_logs
            Assert.Equal(2, rlFields[0].WireType);    // length-delimited
        }

        [Fact]
        public void Serialize_ProducesValidScopeLogs_WithScopeAndLogRecord()
        {
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"));

            var scopeLogs = NavigateToScopeLogs(output);
            var slFields = ReadProtobufFields(scopeLogs);

            // ScopeLogs { InstrumentationScope scope = 1; repeated LogRecord log_records = 2 }
            Assert.True(slFields.Count >= 2);
            Assert.Equal(1, slFields[0].FieldNumber); // scope
            Assert.Equal(2, slFields[0].WireType);
            Assert.Equal(2, slFields[1].FieldNumber); // log_records
            Assert.Equal(2, slFields[1].WireType);
        }

        [Fact]
        public void Serialize_InstrumentationScope_ContainsScopeName()
        {
            var serializer = new OtlpProtobufSerializer();
            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"), scopeName: "MyInstrumentation");

            var scopeLogs = NavigateToScopeLogs(output);
            var slFields = ReadProtobufFields(scopeLogs);
            var scopeField = slFields.Find(f => f.FieldNumber == 1);

            // InstrumentationScope { string name = 1 }
            var scopeFields = ReadProtobufFields(scopeField.Data);
            var nameField = scopeFields.Find(f => f.FieldNumber == 1);
            Assert.Equal(2, nameField.WireType);
            Assert.Equal("MyInstrumentation", Encoding.UTF8.GetString(nameField.Data));
        }

        [Fact]
        public void Serialize_EmptyScopeName_OmitsScopeField()
        {
            var serializer = new OtlpProtobufSerializer();
            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"), scopeName: "");

            var scopeLogs = NavigateToScopeLogs(output);
            var slFields = ReadProtobufFields(scopeLogs);

            // Without scope name only log_records (field 2) should be present
            Assert.DoesNotContain(slFields, f => f.FieldNumber == 1);
            Assert.Contains(slFields, f => f.FieldNumber == 2);
        }

        [Fact]
        public void Serialize_MultipleEvents_ProducesMultipleLogRecords()
        {
            var serializer = new OtlpProtobufSerializer();

            var logEvents = new List<LogEventInfo>
            {
                LogEventInfo.Create(LogLevel.Info, "L", "first"),
                LogEventInfo.Create(LogLevel.Warn, "L", "second"),
                LogEventInfo.Create(LogLevel.Error, "L", "third"),
            };

            var output = SerializeAll(serializer, logEvents);

            var topFields = ReadProtobufFields(output);
            Assert.Equal(3, topFields.FindAll(f => f.FieldNumber == 1).Count);
        }

        #endregion

        #region LogRecord field tests

        [Fact]
        public void Serialize_LogRecord_TimestampIsFixed64UnixNanoseconds()
        {
            // Use a known UTC timestamp
            var knownTime = new DateTime(2024, 6, 15, 12, 0, 0, DateTimeKind.Utc);
            var logEvent = new LogEventInfo(LogLevel.Info, "Logger", "msg") { TimeStamp = knownTime };

            var serializer = new OtlpProtobufSerializer();
            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);
            var timestampField = lrFields.Find(f => f.FieldNumber == 1);

            // time_unix_nano = fixed64 (wire type 1), 8 bytes
            Assert.Equal(1, timestampField.WireType);
            Assert.Equal(8, timestampField.Data.Length);

            var encodedNano = BitConverter.ToUInt64(timestampField.Data, 0);
            var expectedNano = OtlpProtobufSerializer.ToUnixNano(knownTime);
            Assert.Equal(expectedNano, encodedNano);
        }

        [Theory]
        [InlineData("Trace", 1)]
        [InlineData("Debug", 5)]
        [InlineData("Info", 9)]
        [InlineData("Warn", 13)]
        [InlineData("Error", 17)]
        [InlineData("Fatal", 21)]
        public void Serialize_LogRecord_SeverityNumberMappedCorrectly(string levelName, int expectedSeverityNumber)
        {
            var level = LogLevel.FromString(levelName);
            var logEvent = LogEventInfo.Create(level, "Logger", "msg");
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            // severity_number = field 2, varint (wire type 0)
            var severityNumberField = lrFields.Find(f => f.FieldNumber == 2);
            Assert.Equal(0, severityNumberField.WireType);
            var severityNumber = (int)ReadVarintFromBytes(severityNumberField.Data);
            Assert.Equal(expectedSeverityNumber, severityNumber);

            // severity_text = field 3, length-delimited (wire type 2)
            var severityTextField = lrFields.Find(f => f.FieldNumber == 3);
            Assert.Equal(2, severityTextField.WireType);
            Assert.Equal(levelName, Encoding.UTF8.GetString(severityTextField.Data));
        }

        [Fact]
        public void Serialize_LogRecord_BodyEncodedAsAnyValueStringValue()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "hello world");

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            // body = field 5, AnyValue { string string_value = 1 }
            var bodyField = lrFields.Find(f => f.FieldNumber == 5);
            Assert.Equal(2, bodyField.WireType);

            var anyValueFields = ReadProtobufFields(bodyField.Data);
            Assert.Equal(1, anyValueFields[0].FieldNumber); // string_value
            Assert.Equal(2, anyValueFields[0].WireType);    // length-delimited
            Assert.Equal("hello world", Encoding.UTF8.GetString(anyValueFields[0].Data));
        }

        [Fact]
        public void Serialize_LogRecord_EmptyBodyFieldOmitted()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "");

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            // body (field 5) should not be present when the rendered body is empty
            Assert.DoesNotContain(lrFields, f => f.FieldNumber == 5);
        }

        [Fact]
        public void Serialize_LogRecord_LoggerNameEncodedAsAttribute()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "MyApp.Service", "msg");

            var output = Serialize(serializer, logEvent);

            var attributes = GetLogRecordAttributes(output);
            Assert.True(attributes.TryGetValue("LoggerName", out var loggerNameValue));

            var anyValue = ReadProtobufFields(loggerNameValue.Data);
            Assert.Equal(1, anyValue[0].FieldNumber); // string_value
            Assert.Equal("MyApp.Service", Encoding.UTF8.GetString(anyValue[0].Data));
        }

        [Fact]
        public void Serialize_LogRecord_ExceptionAttributesPresent()
        {
            var serializer = new OtlpProtobufSerializer();
            var exception = new InvalidOperationException("something went wrong");
            var logEvent = LogEventInfo.Create(LogLevel.Error, "Logger", exception, null, "error occurred");

            var output = Serialize(serializer, logEvent);

            var attributes = GetLogRecordAttributes(output);

            Assert.True(attributes.ContainsKey("exception.type"));
            var typeAnyValue = ReadProtobufFields(attributes["exception.type"].Data);
            Assert.Contains("InvalidOperationException", Encoding.UTF8.GetString(typeAnyValue[0].Data));

            Assert.True(attributes.ContainsKey("exception.message"));
            var msgAnyValue = ReadProtobufFields(attributes["exception.message"].Data);
            Assert.Equal("something went wrong", Encoding.UTF8.GetString(msgAnyValue[0].Data));

            Assert.True(attributes.ContainsKey("exception.stacktrace"));
            var stackAnyValue = ReadProtobufFields(attributes["exception.stacktrace"].Data);
            Assert.Contains("InvalidOperationException", Encoding.UTF8.GetString(stackAnyValue[0].Data));
        }

        [Fact]
        public void Serialize_LogRecord_EventPropertiesIncludedWhenEnabled()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = new LogEventInfo(LogLevel.Info, "Logger", "msg");
            logEvent.Properties["MyKey"] = "MyValue";

            var output = Serialize(serializer, logEvent);

            var attributes = GetLogRecordAttributes(output);
            Assert.True(attributes.ContainsKey("MyKey"));
            var anyValue = ReadProtobufFields(attributes["MyKey"].Data);
            Assert.Equal("MyValue", Encoding.UTF8.GetString(anyValue[0].Data));
        }

        [Fact]
        public void Serialize_LogRecord_TraceIdEncodedAs16Bytes()
        {
            const string traceIdHex = "0af7651916cd43dd8448eb211c80319c";
            var serializer = new OtlpProtobufSerializer
            {
                TraceId = NLog.Layouts.Layout<System.Diagnostics.ActivityTraceId?>.FromMethod(l => System.Diagnostics.ActivityTraceId.CreateFromString(traceIdHex.AsSpan()))
            };
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "msg");

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            // trace_id = field 9, bytes (wire type 2), exactly 16 bytes
            var traceIdField = lrFields.Find(f => f.FieldNumber == 9);
            Assert.Equal(2, traceIdField.WireType);
            Assert.Equal(16, traceIdField.Data.Length);
            Assert.Equal(traceIdHex, ToHex(traceIdField.Data));
        }

        [Fact]
        public void Serialize_LogRecord_SpanIdEncodedAs8Bytes()
        {
            const string spanIdHex = "b7ad6b7169203331";
            var serializer = new OtlpProtobufSerializer
            {
                SpanId = NLog.Layouts.Layout<System.Diagnostics.ActivitySpanId?>.FromMethod(l => System.Diagnostics.ActivitySpanId.CreateFromString(spanIdHex.AsSpan())),
            };
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "msg");

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            // span_id = field 10, bytes (wire type 2), exactly 8 bytes
            var spanIdField = lrFields.Find(f => f.FieldNumber == 10);
            Assert.Equal(2, spanIdField.WireType);
            Assert.Equal(8, spanIdField.Data.Length);
            Assert.Equal(spanIdHex, ToHex(spanIdField.Data));
        }

        [Fact]
        public void Serialize_LogRecord_TraceIdAndSpanId_OmittedWhenEmpty()
        {
            var serializer = new OtlpProtobufSerializer
            {
                TraceId = NLog.Layouts.Layout<System.Diagnostics.ActivityTraceId?>.FromMethod(l => default(System.Diagnostics.ActivityTraceId?)),
                SpanId = NLog.Layouts.Layout<System.Diagnostics.ActivitySpanId?>.FromMethod(l => default(System.Diagnostics.ActivitySpanId?)),
            };
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "msg");

            var output = Serialize(serializer, logEvent);

            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);

            Assert.DoesNotContain(lrFields, f => f.FieldNumber == 9);
            Assert.DoesNotContain(lrFields, f => f.FieldNumber == 10);
        }

        #endregion

        #region Resource tests

        [Fact]
        public void Serialize_Resource_AdditionalResourceAttributesPresent()
        {
            var serializer = new OtlpProtobufSerializer();
            var resourceAttributes = new List<TargetPropertyWithContext>
            {
                new TargetPropertyWithContext { Name = "deployment.environment", Layout = "production" },
                new TargetPropertyWithContext { Name = "host.name", Layout = "server01" },
            };

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"), resourceAttributes);

            var resourceAttrs = GetResourceAttributes(output);
            Assert.True(resourceAttrs.ContainsKey("deployment.environment"));
            var envAnyValue = ReadProtobufFields(resourceAttrs["deployment.environment"].Data);
            Assert.Equal("production", Encoding.UTF8.GetString(envAnyValue[0].Data));

            Assert.True(resourceAttrs.ContainsKey("host.name"));
            var hostAnyValue = ReadProtobufFields(resourceAttrs["host.name"].Data);
            Assert.Equal("server01", Encoding.UTF8.GetString(hostAnyValue[0].Data));
        }

        [Fact]
        public void Serialize_Resource_AttributeWithEmptyValueIncludedWhenForced()
        {
            var serializer = new OtlpProtobufSerializer();
            var resourceAttributes = new List<TargetPropertyWithContext>
            {
                new TargetPropertyWithContext
                {
                    Name = "forced.attr",
                    Layout = "",
                    IncludeEmptyValue = true,
                },
            };

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"), resourceAttributes);

            var resourceAttrs = GetResourceAttributes(output);
            Assert.True(resourceAttrs.ContainsKey("forced.attr"));
        }

        #endregion

        #region AnyValue encoding tests

        [Fact]
        public void AnyValue_Bool_True_EncodedAsVarintField2Value1()
        {
            var output = SerializeWithProperty("flag", true);
            var anyValue = GetPropertyAnyValue(output, "flag");

            // AnyValue { bool bool_value = 2 } → field 2, wire type 0 (varint), value 1
            Assert.Equal(2, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.WireType);
            Assert.Equal(1UL, ReadVarintFromBytes(anyValue.Data));
        }

        [Fact]
        public void AnyValue_Bool_False_EncodedAsVarintField2Value0()
        {
            var output = SerializeWithProperty("flag", false);
            var anyValue = GetPropertyAnyValue(output, "flag");

            Assert.Equal(2, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.WireType);
            Assert.Equal(0UL, ReadVarintFromBytes(anyValue.Data));
        }

        [Fact]
        public void AnyValue_Int32_EncodedAsVarintField3()
        {
            var output = SerializeWithProperty("count", 42);
            var anyValue = GetPropertyAnyValue(output, "count");

            // AnyValue { int64 int_value = 3 } → field 3, wire type 0 (varint)
            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.WireType);
            Assert.Equal(42UL, ReadVarintFromBytes(anyValue.Data));
        }

        [Fact]
        public void AnyValue_NegativeInt_EncodedAsVarintField3WithZigzagTwosComplement()
        {
            var output = SerializeWithProperty("neg", -1);
            var anyValue = GetPropertyAnyValue(output, "neg");

            // Negative values use two's complement encoding (int64 → ulong cast)
            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.WireType);
            var raw = ReadVarintFromBytes(anyValue.Data);
            Assert.Equal(-1L, unchecked((long)raw));
        }

        [Fact]
        public void AnyValue_UInt64_EncodedAsVarintField3()
        {
            var output = SerializeWithProperty("big", ulong.MaxValue);
            var anyValue = GetPropertyAnyValue(output, "big");

            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.WireType);
            Assert.Equal(ulong.MaxValue, ReadVarintFromBytes(anyValue.Data));
        }

        [Fact]
        public void AnyValue_Double_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("ratio", 3.14);
            var anyValue = GetPropertyAnyValue(output, "ratio");

            // AnyValue { double double_value = 4 } → field 4, wire type 1 (fixed64)
            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(1, anyValue.WireType);
            Assert.Equal(8, anyValue.Data.Length);
            Assert.Equal(3.14, BitConverter.ToDouble(anyValue.Data, 0), precision: 10);
        }

        [Fact]
        public void AnyValue_Float_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("f", 1.5f);
            var anyValue = GetPropertyAnyValue(output, "f");

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(1, anyValue.WireType);
        }

        [Fact]
        public void AnyValue_String_EncodedAsLengthDelimitedField1()
        {
            var output = SerializeWithProperty("msg", "hello");
            var anyValue = GetPropertyAnyValue(output, "msg");

            // AnyValue { string string_value = 1 } → field 1, wire type 2 (length-delimited)
            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Equal(2, anyValue.WireType);
            Assert.Equal("hello", Encoding.UTF8.GetString(anyValue.Data));
        }

        [Fact]
        public void AnyValue_Enum_EncodedAsStringField1()
        {
            var output = SerializeWithProperty("level", System.Diagnostics.TraceEventType.Warning);
            var anyValue = GetPropertyAnyValue(output, "level");

            // Enums are serialized as their name string
            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Equal(2, anyValue.WireType);
            Assert.Equal("Warning", Encoding.UTF8.GetString(anyValue.Data));
        }

        [Fact]
        public void AnyValue_DateTime_EncodedAsIso8601StringField1()
        {
            var dt = new DateTime(2024, 1, 15, 10, 30, 0, DateTimeKind.Utc);
            var output = SerializeWithProperty("ts", dt);
            var anyValue = GetPropertyAnyValue(output, "ts");

            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Equal(2, anyValue.WireType);
            var str = Encoding.UTF8.GetString(anyValue.Data);
            Assert.Contains("2024-01-15", str);
        }

        [Fact]
        public void AnyValue_DoubleNaN_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("nan", double.NaN);
            var anyValue = GetPropertyAnyValue(output, "nan");

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(1, anyValue.WireType);
            Assert.Equal(8, anyValue.Data.Length);
            Assert.True(double.IsNaN(BitConverter.ToDouble(anyValue.Data, 0)));
        }

        [Fact]
        public void AnyValue_DoublePositiveInfinity_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("inf", double.PositiveInfinity);
            var anyValue = GetPropertyAnyValue(output, "inf");

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(1, anyValue.WireType);
            Assert.True(double.IsPositiveInfinity(BitConverter.ToDouble(anyValue.Data, 0)));
        }

        [Fact]
        public void AnyValue_List_EncodedAsArrayValueField5()
        {
            var list = new List<object> { "alpha", 99, true };
            var output = SerializeWithProperty("items", list);
            var anyValueWrapper = GetPropertyAnyValueWrapper(output, "items");

            // AnyValue { ArrayValue array_value = 5 } → field 5, wire type 2
            var wrapperFields = ReadProtobufFields(anyValueWrapper.Data);
            var arrayField = wrapperFields.Find(f => f.FieldNumber == 5);
            Assert.Equal(2, arrayField.WireType);

            // ArrayValue { repeated AnyValue values = 1 }
            var arrayEntries = ReadProtobufFields(arrayField.Data);
            Assert.Equal(3, arrayEntries.Count);
            Assert.All(arrayEntries, e => Assert.Equal(1, e.FieldNumber));

            // "alpha" → string_value (field 1)
            var elem0 = ReadProtobufFields(arrayEntries[0].Data);
            Assert.Equal(1, elem0[0].FieldNumber);
            Assert.Equal("alpha", Encoding.UTF8.GetString(elem0[0].Data));

            // 99 → int_value (field 3)
            var elem1 = ReadProtobufFields(arrayEntries[1].Data);
            Assert.Equal(3, elem1[0].FieldNumber);
            Assert.Equal(99UL, ReadVarintFromBytes(elem1[0].Data));

            // true → bool_value (field 2)
            var elem2 = ReadProtobufFields(arrayEntries[2].Data);
            Assert.Equal(2, elem2[0].FieldNumber);
            Assert.Equal(1UL, ReadVarintFromBytes(elem2[0].Data));
        }

        [Fact]
        public void AnyValue_Dictionary_EncodedAsKvListValueField6()
        {
            var dict = new Dictionary<string, object>
            {
                ["key1"] = "value1",
                ["key2"] = 42,
            };
            var output = SerializeWithProperty("map", dict);
            var anyValueWrapper = GetPropertyAnyValueWrapper(output, "map");

            // AnyValue { KeyValueList kvlist_value = 6 } → field 6, wire type 2
            var wrapperFields = ReadProtobufFields(anyValueWrapper.Data);
            var kvListField = wrapperFields.Find(f => f.FieldNumber == 6);
            Assert.Equal(2, kvListField.WireType);

            // KeyValueList { repeated KeyValue values = 1 }
            var kvEntries = ReadProtobufFields(kvListField.Data);
            Assert.Equal(2, kvEntries.Count);

            var parsed = new Dictionary<string, ProtobufField>();
            foreach (var entry in kvEntries)
            {
                var entryFields = ReadProtobufFields(entry.Data);
                var key = Encoding.UTF8.GetString(entryFields.Find(f => f.FieldNumber == 1).Data);
                parsed[key] = entryFields.Find(f => f.FieldNumber == 2);
            }

            // key1 → string_value
            var key1AnyValue = ReadProtobufFields(parsed["key1"].Data);
            Assert.Equal(1, key1AnyValue[0].FieldNumber);
            Assert.Equal("value1", Encoding.UTF8.GetString(key1AnyValue[0].Data));

            // key2 → int_value
            var key2AnyValue = ReadProtobufFields(parsed["key2"].Data);
            Assert.Equal(3, key2AnyValue[0].FieldNumber);
            Assert.Equal(42UL, ReadVarintFromBytes(key2AnyValue[0].Data));
        }

        [Fact]
        public void AnyValue_NullValue_AttributeKeyPresentWithoutValueField()
        {
            var output = SerializeWithProperty("n", (object)null);

            // null is converted to empty string → WriteStringField skips it → AnyValue is omitted.
            // The KeyValue attribute is still written (key = "n") but carries no value submessage.
            var logRecord = NavigateToLogRecord(output);
            var lrFields = ReadProtobufFields(logRecord);
            var attributeFields = lrFields.FindAll(f => f.FieldNumber == 6);

            // Find the KeyValue whose key is "n"
            var found = false;
            foreach (var kv in attributeFields)
            {
                var kvFields = ReadProtobufFields(kv.Data);
                var keyField = kvFields.Find(f => f.FieldNumber == 1);
                if (keyField.Data != null && Encoding.UTF8.GetString(keyField.Data) == "n")
                {
                    found = true;
                    // No value field (field 2) should be present
                    Assert.DoesNotContain(kvFields, f => f.FieldNumber == 2);
                    break;
                }
            }
            Assert.True(found, "Attribute 'n' should be present in the log record");
        }

        #endregion

        #region Helper methods for building serializer output

        private static byte[] Serialize(OtlpProtobufSerializer serializer, LogEventInfo logEvent, string scopeName = "NLog")
        {
            var output = new MemoryStream();
            using (var builder = serializer.BeginRecord(output))
            {
                var logProperties = logEvent.HasProperties ? logEvent.Properties.ToDictionary(d => d.Key.ToString(), d => d.Value) : null;
                builder.AddScopeLogs(scopeName, logEvent, logEvent.FormattedMessage, logProperties);
            }
            return output.ToArray();
        }

        private static byte[] Serialize(OtlpProtobufSerializer serializer, LogEventInfo logEvent, IList<TargetPropertyWithContext> resourceAttributes, string scopeName = "NLog")
        {
            var output = new MemoryStream();
            using (var builder = serializer.BeginRecord(output))
            {
                for (int i = 0; i < resourceAttributes.Count; i++)
                    builder.AddResourceAttribute(resourceAttributes[i].Name, resourceAttributes[i].Layout?.Render(logEvent));

                var logProperties = logEvent.HasProperties ? logEvent.Properties.ToDictionary(d => d.Key.ToString(), d => d.Value) : null;
                builder.AddScopeLogs(scopeName, logEvent, logEvent.FormattedMessage, logProperties);
            }
            return output.ToArray();
        }

        private static byte[] SerializeAll(OtlpProtobufSerializer serializer, IList<LogEventInfo> logEvents, string scopeName = "NLog")
        {
            var output = new MemoryStream();
            for (int i = 0; i < logEvents.Count; i++)
            {
                using (var builder = serializer.BeginRecord(output))
                {
                    var logProperties = logEvents[i].HasProperties ? logEvents[i].Properties.ToDictionary(d => d.Key.ToString(), d => d.Value) : null;
                    builder.AddScopeLogs(scopeName, logEvents[i], logEvents[i].FormattedMessage, logProperties);
                }
            }
            return output.ToArray();
        }

        private static byte[] SerializeWithProperty(string key, object value)
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = new LogEventInfo(LogLevel.Info, "Logger", "msg");
            logEvent.Properties[key] = value;
            return Serialize(serializer, logEvent);
        }

        #endregion

        #region Protobuf navigation helpers

        private static byte[] NavigateToScopeLogs(byte[] data)
        {
            var topFields = ReadProtobufFields(data);
            var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
            return resourceLogs.Find(f => f.FieldNumber == 2).Data;
        }

        private static byte[] NavigateToLogRecord(byte[] data)
        {
            var scopeLogs = NavigateToScopeLogs(data);
            var slFields = ReadProtobufFields(scopeLogs);
            return slFields.Find(f => f.FieldNumber == 2).Data;
        }

        private static Dictionary<string, ProtobufField> GetLogRecordAttributes(byte[] data)
        {
            var logRecord = NavigateToLogRecord(data);
            var lrFields = ReadProtobufFields(logRecord);
            var attributeFields = lrFields.FindAll(f => f.FieldNumber == 6);
            return ParseKeyValueFields(attributeFields);
        }

        private static Dictionary<string, ProtobufField> GetResourceAttributes(byte[] data)
        {
            var topFields = ReadProtobufFields(data);
            var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
            var resource = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 1).Data);
            var attributeFields = resource.FindAll(f => f.FieldNumber == 1);
            return ParseKeyValueFields(attributeFields);
        }

        private static Dictionary<string, ProtobufField> ParseKeyValueFields(List<ProtobufField> kvFields)
        {
            var result = new Dictionary<string, ProtobufField>();
            foreach (var kv in kvFields)
            {
                var fields = ReadProtobufFields(kv.Data);
                var keyField = fields.Find(f => f.FieldNumber == 1);
                var valueField = fields.Find(f => f.FieldNumber == 2);
                if (keyField.Data?.Length > 0)
                    result[Encoding.UTF8.GetString(keyField.Data)] = valueField;
            }
            return result;
        }

        /// <summary>
        /// Returns the decoded inner AnyValue field (e.g. string_value=1, int_value=3) for an event property.
        /// </summary>
        private static ProtobufField GetPropertyAnyValue(byte[] data, string propertyKey)
        {
            var wrapper = GetPropertyAnyValueWrapper(data, propertyKey);
            var anyValueFields = ReadProtobufFields(wrapper.Data);
            return anyValueFields[0];
        }

        /// <summary>
        /// Returns the raw AnyValue submessage field (field 2 of the KeyValue) for an event property.
        /// </summary>
        private static ProtobufField GetPropertyAnyValueWrapper(byte[] data, string propertyKey)
        {
            var attrs = GetLogRecordAttributes(data);
            Assert.True(attrs.TryGetValue(propertyKey, out var wrapper), $"Property '{propertyKey}' not found in log record attributes");
            return wrapper;
        }

        private static string ToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        #endregion

        #region Protobuf reader helpers

        private struct ProtobufField
        {
            public int FieldNumber;
            public int WireType;
            public byte[] Data;
        }

        private static List<ProtobufField> ReadProtobufFields(byte[] data)
        {
            var fields = new List<ProtobufField>();
            int offset = 0;
            while (offset < data.Length)
            {
                var tag = ReadVarint(data, ref offset);
                var fieldNumber = (int)(tag >> 3);
                var wireType = (int)(tag & 0x7);

                byte[] fieldData;
                switch (wireType)
                {
                    case 0: // varint
                        var start = offset;
                        ReadVarint(data, ref offset);
                        fieldData = new byte[offset - start];
                        Array.Copy(data, start, fieldData, 0, fieldData.Length);
                        break;
                    case 1: // 64-bit fixed
                        fieldData = new byte[8];
                        Array.Copy(data, offset, fieldData, 0, 8);
                        offset += 8;
                        break;
                    case 2: // length-delimited
                        var length = (int)ReadVarint(data, ref offset);
                        fieldData = new byte[length];
                        Array.Copy(data, offset, fieldData, 0, length);
                        offset += length;
                        break;
                    case 5: // 32-bit fixed
                        fieldData = new byte[4];
                        Array.Copy(data, offset, fieldData, 0, 4);
                        offset += 4;
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown protobuf wire type {wireType} at offset {offset}");
                }

                fields.Add(new ProtobufField { FieldNumber = fieldNumber, WireType = wireType, Data = fieldData });
            }
            return fields;
        }

        private static ulong ReadVarint(byte[] data, ref int offset)
        {
            ulong value = 0;
            int shift = 0;
            while (offset < data.Length)
            {
                var b = data[offset++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                    break;
                shift += 7;
            }
            return value;
        }

        private static ulong ReadVarintFromBytes(byte[] data)
        {
            int offset = 0;
            return ReadVarint(data, ref offset);
        }

        #endregion
    }
}
