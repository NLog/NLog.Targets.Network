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

namespace NLog.Targets.OpenTelemetryHttp.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using NLog.Internal;
    using Xunit;

    /// <summary>
    /// Unit tests for <see cref="OtlpProtobufSerializer"/> that validate protobuf output
    /// against the OpenTelemetry OTLP logs.proto specification without requiring an HTTP server.
    /// </summary>
    /// <remarks>
    /// Proto field references (OTLP Logs v1):
    ///
    /// ExportLogsServiceRequest { repeated ResourceLogs resource_logs = 1 }
    ///
    /// ResourceLogs {
    ///   Resource resource = 1;
    ///   repeated ScopeLogs scope_logs = 2
    /// }
    ///
    /// Resource {
    ///   repeated KeyValue attributes = 1;
    ///   uint32 dropped_attributes_count = 2
    /// }
    ///
    /// ScopeLogs {
    ///   InstrumentationScope scope = 1;
    ///   repeated LogRecord log_records = 2
    /// }
    ///
    /// InstrumentationScope {
    ///   string name = 1
    /// }
    ///
    /// LogRecord {
    ///   fixed64 time_unix_nano = 1;
    ///   SeverityNumber severity_number = 2 (enum);
    ///   string severity_text = 3;
    ///   AnyValue body = 5;
    ///   repeated KeyValue attributes = 6;
    ///   bytes trace_id = 9 (16 bytes);
    ///   bytes span_id = 10 (8 bytes)
    /// }
    ///
    /// AnyValue {
    ///   string string_value = 1;
    ///   bool bool_value = 2;
    ///   int64 int_value = 3;
    ///   double double_value = 4;
    ///   ArrayValue array_value = 5;
    ///   KeyValueList kvlist_value = 6
    /// }
    ///
    /// KeyValue {
    ///   string key = 1;
    ///   AnyValue value = 2
    /// }
    ///
    /// ArrayValue {
    ///   repeated AnyValue values = 1
    /// }
    ///
    /// KeyValueList {
    ///   repeated KeyValue values = 1
    /// }
    /// </remarks>
    public class OtlpProtobufSerializerTests
    {
        #region Structure tests

        [Fact]
        public void Serialize_ProducesValidExportLogsServiceRequest_TopLevelStructure()
        {
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "hello"));

            // ExportLogsServiceRequest → ResourceLogs → ScopeLogs
            var logRecords = ProtobufParser.GetLogRecords(output);

            Assert.Single(logRecords);
        }

        [Fact]
        public void Serialize_ProducesValidScopeLogs_WithScopeAndLogRecord()
        {
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, LogEventInfo.Create(LogLevel.Info, "Logger", "msg"));

            var scopeLogs = ProtobufParser.GetScopeLogs(output);
            var slFields = scopeLogs.AsMessage();

            // ScopeLogs { InstrumentationScope scope = 1; repeated LogRecord log_records = 2 }

            var scopeFields = slFields.FindAll(f => f.FieldNumber == 1);
            var logRecordFields = slFields.FindAll(f => f.FieldNumber == 2);

            Assert.Single(scopeFields);        // exactly one scope message
            Assert.NotEmpty(logRecordFields);  // at least one log record

            var scopeField = scopeFields[0];
            var logRecordField = logRecordFields[0];

            Assert.Equal(2, scopeField.WireType);      // length-delimited
            Assert.Equal(2, logRecordField.WireType);  // length-delimited
        }

        [Fact]
        public void Serialize_InstrumentationScope_ContainsScopeName()
        {
            var serializer = new OtlpProtobufSerializer();
            var output = Serialize(
                serializer,
                LogEventInfo.Create(LogLevel.Info, "Logger", "msg"),
                scopeName: "MyInstrumentation");

            var scopeLogs = ProtobufParser.GetScopeLogs(output);
            var slFields = scopeLogs.AsMessage();

            var scopeField = slFields.GetField(1);
            Assert.Equal(2, scopeField.WireType);

            var nameField = scopeField.GetField(1);
            Assert.Equal("MyInstrumentation", nameField.AsString());
        }

        [Fact]
        public void Serialize_EmptyScopeName_OmitsScopeField()
        {
            var serializer = new OtlpProtobufSerializer();
            var output = Serialize(
                serializer,
                LogEventInfo.Create(LogLevel.Info, "Logger", "msg"),
                scopeName: "");

            var scopeLogs = ProtobufParser.GetScopeLogs(output);
            var slFields = scopeLogs.AsMessage();

            // ScopeLogs should not contain InstrumentationScope (field 1)
            var scopeFields = slFields.FindAll(f => f.FieldNumber == 1);
            Assert.Empty(scopeFields);

            // But log_records (field 2) must still be present
            var logRecordFields = slFields.FindAll(f => f.FieldNumber == 2);
            Assert.NotEmpty(logRecordFields);

            foreach (var lr in logRecordFields)
                Assert.Equal(2, lr.WireType); // length-delimited
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
            var logRecords = ProtobufParser.GetLogRecords(output);
            Assert.Equal(3, logRecords.Count);
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

            var logRecord = ProtobufParser.GetLogRecord(output);
            var timestampField = logRecord.AsMessage().GetField(1);

            // time_unix_nano = fixed64 (wire type 1), 8 bytes
            var encodedNano = timestampField.AsUInt64();
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
        public void Serialize_LogRecord_SeverityNumberMappedCorrectly(
            string levelName,
            int expectedSeverityNumber)
        {
            var level = LogLevel.FromString(levelName);
            var logEvent = LogEventInfo.Create(level, "Logger", "msg");
            var serializer = new OtlpProtobufSerializer();

            var output = Serialize(serializer, logEvent);

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

            // severity_number = field 2 (varint)
            var severityNumberField = lrFields.GetField(2);
            Assert.Equal(expectedSeverityNumber, severityNumberField.AsInt64());

            // severity_text = field 3 (string)
            var severityTextField = lrFields.GetField(3);
            Assert.Equal(levelName, severityTextField.AsString());
        }

        [Fact]
        public void Serialize_LogRecord_BodyEncodedAsAnyValueStringValue()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "hello world");

            var output = Serialize(serializer, logEvent);

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

            // body = field 5 (AnyValue)
            var bodyField = lrFields.GetField(5);
            Assert.Equal(2, bodyField.WireType);

            // AnyValue structure
            var anyValue = bodyField.AsMessage();
            var stringValueField = anyValue.GetField(1);
            Assert.Equal("hello world", stringValueField.AsString());
        }

        [Fact]
        public void Serialize_LogRecord_EmptyBodyFieldOmitted()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "Logger", "");

            var output = Serialize(serializer, logEvent);

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

            // body (field 5) should not be present when the rendered body is empty
            Assert.DoesNotContain(lrFields, f => f.FieldNumber == 5);
        }

        [Fact]
        public void Serialize_LogRecord_LoggerNameEncodedAsAttribute()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = LogEventInfo.Create(LogLevel.Info, "MyApp.Service", "msg");

            var output = Serialize(serializer, logEvent);

            var attributes = ProtobufParser.GetLogRecordAttributes(output);
            Assert.True(attributes.TryGetValue("logger.name", out var loggerNameValue));

            var stringValue = loggerNameValue.GetField(1).AsString();
            Assert.Equal("MyApp.Service", stringValue);
        }

        [Fact]
        public void Serialize_LogRecord_ExceptionAttributesPresent()
        {
            var serializer = new OtlpProtobufSerializer();
            var exception = new InvalidOperationException("something went wrong");
            var logEvent = LogEventInfo.Create(LogLevel.Error, "Logger", exception, null, "error occurred");

            var output = Serialize(serializer, logEvent);

            var attributes = ProtobufParser.GetLogRecordAttributes(output);

            Assert.True(attributes.ContainsKey("exception.type"));
            var typeAnyValue = attributes["exception.type"].GetField(1);
            Assert.Contains("InvalidOperationException", typeAnyValue.AsString());

            Assert.True(attributes.ContainsKey("exception.message"));
            var messageAnyValue = attributes["exception.message"].GetField(1);
            Assert.Equal("something went wrong", messageAnyValue.AsString());

            Assert.True(attributes.ContainsKey("exception.stacktrace"));
            var stackAnyValue = attributes["exception.stacktrace"].GetField(1);
            Assert.Contains("InvalidOperationException", stackAnyValue.AsString());
        }

        [Fact]
        public void Serialize_LogRecord_EventPropertiesIncludedWhenEnabled()
        {
            var serializer = new OtlpProtobufSerializer();
            var logEvent = new LogEventInfo(LogLevel.Info, "Logger", "msg");
            logEvent.Properties["MyKey"] = "MyValue";

            var output = Serialize(serializer, logEvent);

            var attributes = ProtobufParser.GetLogRecordAttributes(output);
            Assert.True(attributes.ContainsKey("MyKey"));

            var value = attributes["MyKey"].GetField(1);
            Assert.Equal("MyValue", value.AsString());
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

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

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

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

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

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

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

            var resourceAttrs = ProtobufParser.GetResourceAttributes(output);
            Assert.Equal("production", resourceAttrs["deployment.environment"].AsAnyValueString());
            Assert.Equal("server01", resourceAttrs["host.name"].AsAnyValueString());
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

            var resourceAttrs = ProtobufParser.GetResourceAttributes(output);
            Assert.True(resourceAttrs.ContainsKey("forced.attr"));
        }

        #endregion

        #region AnyValue encoding tests

        [Fact]
        public void AnyValue_Bool_True_EncodedAsVarintField2Value1()
        {
            var output = SerializeWithProperty("flag", true);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["flag"].AsAnyValue();
            Assert.Equal(2, anyValue.FieldNumber);
            Assert.Equal(1, anyValue.AsInt64());
        }

        [Fact]
        public void AnyValue_Bool_False_EncodedAsVarintField2Value0()
        {
            var output = SerializeWithProperty("flag", false);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["flag"].AsAnyValue();
            Assert.Equal(2, anyValue.FieldNumber);
            Assert.Equal(0, anyValue.AsInt64());
        }

        [Fact]
        public void AnyValue_Int32_EncodedAsVarintField3()
        {
            var output = SerializeWithProperty("count", 42);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["count"].AsAnyValue();

            // AnyValue { int64 int_value = 3 } → field 3, wire type 0 (varint)
            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(42, anyValue.AsInt64());
        }

        [Fact]
        public void AnyValue_NegativeInt_EncodedAsVarintField3WithZigzagTwosComplement()
        {
            var output = SerializeWithProperty("neg", -1);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["neg"].AsAnyValue();

            // Negative values use two's complement encoding (int64 → ulong cast)
            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(-1, anyValue.AsInt64());
        }

        [Fact]
        public void AnyValue_UInt64_EncodedAsVarintField3()
        {
            var output = SerializeWithProperty("big", ulong.MaxValue);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["big"].AsAnyValue();

            Assert.Equal(3, anyValue.FieldNumber);
            Assert.Equal(ulong.MaxValue, (ulong)anyValue.AsInt64());
        }

        [Fact]
        public void AnyValue_Double_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("ratio", 3.14);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["ratio"].AsAnyValue();

            // AnyValue { double double_value = 4 } → field 4, wire type 1 (fixed64)
            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(3.14, anyValue.AsDouble(), precision: 10);
        }

        [Fact]
        public void AnyValue_Float_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("f", 1.5f);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["f"].AsAnyValue();

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.Equal(1.5f, anyValue.AsDouble());
        }

        [Fact]
        public void AnyValue_String_EncodedAsLengthDelimitedField1()
        {
            var output = SerializeWithProperty("msg", "hello");
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["msg"].AsAnyValue();

            // AnyValue { string string_value = 1 } → field 1, wire type 2 (length-delimited)
            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Equal("hello", anyValue.AsString());
        }

        [Fact]
        public void AnyValue_Enum_EncodedAsStringField1()
        {
            var output = SerializeWithProperty("level", System.Diagnostics.TraceEventType.Warning);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["level"].AsAnyValue();

            // Enums are serialized as their name string
            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Equal("Warning", anyValue.AsString());
        }

        [Fact]
        public void AnyValue_DateTime_EncodedAsIso8601StringField1()
        {
            var dt = new DateTime(2024, 1, 15, 10, 30, 0, DateTimeKind.Utc);
            var output = SerializeWithProperty("ts", dt);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["ts"].AsAnyValue();

            Assert.Equal(1, anyValue.FieldNumber);
            Assert.Contains("2024-01-15", anyValue.AsString());
        }

        [Fact]
        public void AnyValue_DoubleNaN_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("nan", double.NaN);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["nan"].AsAnyValue();

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.True(double.IsNaN(anyValue.AsDouble()));
        }

        [Fact]
        public void AnyValue_DoublePositiveInfinity_EncodedAsFixed64Field4()
        {
            var output = SerializeWithProperty("inf", double.PositiveInfinity);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValue = logRecordAttributes["inf"].AsAnyValue();

            Assert.Equal(4, anyValue.FieldNumber);
            Assert.True(double.IsPositiveInfinity(anyValue.AsDouble()));
        }

        [Fact]
        public void AnyValue_List_EncodedAsArrayValueField5()
        {
            var list = new List<object> { "alpha", 99, true };
            var output = SerializeWithProperty("items", list);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValueWrapper = logRecordAttributes["items"];
            var array = anyValueWrapper.AsArrayValue();

            Assert.Equal(3, array.Count);

            Assert.Equal("alpha", array[0].GetField(1).AsString());
            Assert.Equal(99L, array[1].GetField(3).AsInt64());
            Assert.Equal(1L, array[2].GetField(2).AsInt64());
        }

        [Fact]
        public void AnyValue_Dictionary_EncodedAsDictionaryValueField6()
        {
            var dict = new Dictionary<string, object>
            {
                ["key1"] = "value1",
                ["key2"] = 42,
            };
            var output = SerializeWithProperty("map", dict);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValueWrapper = logRecordAttributes["map"];

            // AnyValue { KeyValueList kvlist_value = 6 } → field 6, wire type 2
            var map = anyValueWrapper.GetField(6).AsMessage().GetFieldValues(1); // KeyValueList { repeated KeyValue values = 1 }
            Assert.Equal("value1", map["key1"].GetField(1).AsString());
            Assert.Equal(42L, map["key2"].GetField(3).AsInt64());
        }

        [Fact]
        public void AnyValue_Dictionary_Nested_EncodedAsDictionaryValueField6()
        {
            var dict = new Dictionary<string, object>
            {
                ["key1"] = "value1",
                ["key2"] = new List<object> { "alpha", 99, new List<object> { "nested" } },
            };

            var output = SerializeWithProperty("map", dict);
            var logRecordAttributes = ProtobufParser.GetLogRecordAttributes(output);
            var anyValueWrapper = logRecordAttributes["map"];

            // LogRecord.attributes → KeyValue.value (AnyValue)
            // AnyValue.kvlist_value = 6 (map encoded as KeyValueList)
            var map = anyValueWrapper.GetField(6).AsMessage().GetFieldValues(1); // KeyValueList { repeated KeyValue values = 1 }

            // key1 → AnyValue.string_value = 1
            Assert.Equal("value1", map["key1"].GetField(1).AsString());

            // key2 → AnyValue.array_value = 5
            // ArrayValue contains repeated AnyValue elements (field 1)
            var arrayEntries = map["key2"].AsArrayValue();

            Assert.Equal(3, arrayEntries.Count);
            // ArrayValue { repeated AnyValue values = 1 }
            Assert.All(arrayEntries, e => Assert.Equal(1, e.FieldNumber));
        }

        [Fact]
        public void AnyValue_NullValue_AttributeKeyPresentWithoutValueField()
        {
            var output = SerializeWithProperty("n", (object)null);

            var logRecord = ProtobufParser.GetLogRecord(output);
            var lrFields = logRecord.AsMessage();

            var attributes = lrFields.GetFieldValues(6);

            Assert.True(attributes.ContainsKey("n"));

            // KeyValue exists, but value (field 2 inside AnyValue) should NOT exist
            var valueField = attributes["n"];
            Assert.Equal(0, valueField.FieldNumber);
            Assert.Null(valueField.Data);
        }

        #endregion

        #region Helper methods for building serializer output

        private static byte[] Serialize(OtlpProtobufSerializer serializer, LogEventInfo logEvent, string scopeName = "NLog")
        {
            var output = new MemoryStream();
            using (var builder = serializer.BeginRecord(output))
            {
                builder.BeginScope(scopeName);
                var logProperties = logEvent.HasProperties ? logEvent.Properties : null;
                builder.AddLogRecord(logEvent, logEvent.FormattedMessage, logProperties);
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

                builder.BeginScope(scopeName);
                var logProperties = logEvent.HasProperties ? logEvent.Properties : null;
                builder.AddLogRecord(logEvent, logEvent.FormattedMessage, logProperties);
            }
            return output.ToArray();
        }

        private static byte[] SerializeAll(OtlpProtobufSerializer serializer, IList<LogEventInfo> logEvents, string scopeName = "NLog")
        {
            var output = new MemoryStream();
            using (var builder = serializer.BeginRecord(output))
            {
                builder.BeginScope(scopeName);
                for (int i = 0; i < logEvents.Count; i++)
                {
                    var logProperties = logEvents[i].HasProperties ? logEvents[i].Properties : null;
                    builder.AddLogRecord(logEvents[i], logEvents[i].FormattedMessage, logProperties);
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

        private static string ToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        #endregion

        #region Protobuf reader helpers





        #endregion
    }

}
