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
    using System.Diagnostics;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using NLog.Config;
    using Xunit;

    public class OpenTelemetryHttpTests
    {
        public OpenTelemetryHttpTests()
        {
            LogManager.ThrowExceptions = true;
        }

        [Fact]
        public void PostSingleMessage_ProtobufContentType()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ServiceName = "TestService",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello otlp");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.Equal("POST", requests[0].Method);
                Assert.Equal("/v1/logs", requests[0].Path);
                Assert.True(requests[0].Headers.TryGetValue("Content-Type", out var contentType));
                Assert.Contains("application/x-protobuf", contentType);
                Assert.True(requests[0].BodyBytes.Length > 0);
            }
        }

        [Fact]
        public void PostSingleMessage_ContainsLogMessageInProtobuf()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ServiceName = "TestService",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello otlp world");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Protobuf stores strings as raw UTF-8, so the message should appear in the byte stream
                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("hello otlp world", bodyText);
                Assert.Contains("TestService", bodyText);
                Assert.Contains("TestLogger", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_ContainsSeverityText()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Warn("warning message");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("Warn", bodyText);
                Assert.Contains("warning message", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_ContainsScopeName()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ScopeName = "MyInstrumentationScope",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("scoped message");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("MyInstrumentationScope", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_IncludesEventProperties()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = true,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "with props");
                    logEvent.Properties["CustomKey"] = "CustomValue";
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("CustomKey", bodyText);
                Assert.Contains("CustomValue", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_TypedEventProperties_EncodedAsCorrectAnyValueTypes()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = true,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "typed props");
                    logEvent.Properties["BoolProp"] = true;
                    logEvent.Properties["IntProp"] = 42;
                    logEvent.Properties["DoubleProp"] = 3.14;
                    logEvent.Properties["StringProp"] = "hello";
                    logEvent.Properties["EnumProp"] = TraceEventType.Resume;
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord attributes
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // Collect all attribute fields (field 6 = KeyValue in LogRecord)
                var attributes = logRecord.FindAll(f => f.FieldNumber == 6);

                // Parse each KeyValue to extract key name and AnyValue wire type
                var typedAttributes = ParseKeyValueList(attributes);

                // BoolProp: AnyValue field 2 (bool_value), varint wire type 0
                var boolAnyValue = ReadProtobufFields(typedAttributes["BoolProp"].Data);
                Assert.Equal(2, boolAnyValue[0].FieldNumber); // bool_value field
                Assert.Equal(0, boolAnyValue[0].WireType);    // varint

                // IntProp: AnyValue field 3 (int_value), varint wire type 0
                var intAnyValue = ReadProtobufFields(typedAttributes["IntProp"].Data);
                Assert.Equal(3, intAnyValue[0].FieldNumber);  // int_value field
                Assert.Equal(0, intAnyValue[0].WireType);     // varint

                // DoubleProp: AnyValue field 4 (double_value), fixed64 wire type 1
                var doubleAnyValue = ReadProtobufFields(typedAttributes["DoubleProp"].Data);
                Assert.Equal(4, doubleAnyValue[0].FieldNumber); // double_value field
                Assert.Equal(1, doubleAnyValue[0].WireType);    // fixed64

                // StringProp: AnyValue field 1 (string_value), length-delimited wire type 2
                var stringAnyValue = ReadProtobufFields(typedAttributes["StringProp"].Data);
                Assert.Equal(1, stringAnyValue[0].FieldNumber); // string_value field
                Assert.Equal(2, stringAnyValue[0].WireType);    // length-delimited
                Assert.Equal("hello", Encoding.UTF8.GetString(stringAnyValue[0].Data));

                // EnumProp: AnyValue field 1 (string_value), length-delimited wire type 2
                var enumAnyValue = ReadProtobufFields(typedAttributes["EnumProp"].Data);
                Assert.Equal(1, enumAnyValue[0].FieldNumber); // string_value field
                Assert.Equal(2, enumAnyValue[0].WireType);    // length-delimited
                Assert.Equal("Resume", Encoding.UTF8.GetString(enumAnyValue[0].Data));
            }
        }

        private static Dictionary<string, ProtobufField> ParseKeyValueList(List<ProtobufField> attributes)
        {
            var result = new Dictionary<string, ProtobufField>();

            foreach (var attr in attributes)
            {
                var kvFields = ReadProtobufFields(attr.Data);
                var keyField = kvFields.Find(f => f.FieldNumber == 1);
                var valueField = kvFields.Find(f => f.FieldNumber == 2);
                var keyName = Encoding.UTF8.GetString(keyField.Data);
                result.Add(keyName, valueField);
            }

            return result;
        }

        [Fact]
        public void PostSingleMessage_SpecialDoubleValues_EncodedAsFixed64()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = true,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "special doubles");
                    logEvent.Properties["NaNProp"] = double.NaN;
                    logEvent.Properties["PosInfProp"] = double.PositiveInfinity;
                    logEvent.Properties["NegInfProp"] = double.NegativeInfinity;
                    logEvent.Properties["FloatNaNProp"] = float.NaN;
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord attributes
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // Collect all attribute fields
                var attributes = logRecord.FindAll(f => f.FieldNumber == 6);
                var typedAttributes = ParseKeyValueList(attributes);

                // All special doubles should be encoded as double_value (field 4, fixed64 wire type 1)
                var nanAnyValue = ReadProtobufFields(typedAttributes["NaNProp"].Data);
                Assert.Equal(4, nanAnyValue[0].FieldNumber);
                Assert.Equal(1, nanAnyValue[0].WireType);
                Assert.Equal(8, nanAnyValue[0].Data.Length);
                Assert.True(double.IsNaN(BitConverter.ToDouble(nanAnyValue[0].Data, 0)));

                var posInfAnyValue = ReadProtobufFields(typedAttributes["PosInfProp"].Data);
                Assert.Equal(4, posInfAnyValue[0].FieldNumber);
                Assert.Equal(1, posInfAnyValue[0].WireType);
                Assert.True(double.IsPositiveInfinity(BitConverter.ToDouble(posInfAnyValue[0].Data, 0)));

                var negInfAnyValue = ReadProtobufFields(typedAttributes["NegInfProp"].Data);
                Assert.Equal(4, negInfAnyValue[0].FieldNumber);
                Assert.Equal(1, negInfAnyValue[0].WireType);
                Assert.True(double.IsNegativeInfinity(BitConverter.ToDouble(negInfAnyValue[0].Data, 0)));

                // float.NaN should also be encoded as double_value (TypeCode.Single → ToDouble)
                var floatNanAnyValue = ReadProtobufFields(typedAttributes["FloatNaNProp"].Data);
                Assert.Equal(4, floatNanAnyValue[0].FieldNumber);
                Assert.Equal(1, floatNanAnyValue[0].WireType);
                Assert.True(double.IsNaN(BitConverter.ToDouble(floatNanAnyValue[0].Data, 0)));
            }
        }

        [Fact]
        public void PostSingleMessage_DictionaryProperty_EncodedAsKvListAnyValue()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = true,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "dict prop");
                    logEvent.Properties["MapProp"] = new Dictionary<string, object>
                    {
                        ["nestedKey"] = "nestedValue",
                        ["nestedInt"] = 42,
                    };
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord attributes
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // Find the MapProp attribute
                var attributes = logRecord.FindAll(f => f.FieldNumber == 6);
                ProtobufField mapAnyValue = default;
                for (int i = 0; i < attributes.Count; i++)
                {
                    var kvFields = ReadProtobufFields(attributes[i].Data);
                    var keyField = kvFields.Find(f => f.FieldNumber == 1);
                    if (Encoding.UTF8.GetString(keyField.Data) == "MapProp")
                    {
                        mapAnyValue = kvFields.Find(f => f.FieldNumber == 2);
                        break;
                    }
                }
                Assert.True(mapAnyValue.Data.Length > 0, "MapProp attribute should be present");

                // AnyValue field 6 = kvlist_value (wire type 2, length-delimited)
                var anyValueFields = ReadProtobufFields(mapAnyValue.Data);
                var kvListField = anyValueFields.Find(f => f.FieldNumber == 6);
                Assert.Equal(2, kvListField.WireType);

                // KeyValueList { repeated KeyValue values = 1 }
                var kvListEntries = ReadProtobufFields(kvListField.Data);
                Assert.Equal(2, kvListEntries.Count);

                // Parse nested entries
                var nestedEntries = ParseKeyValueList(kvListEntries);

                // nestedKey should be string_value (AnyValue field 1)
                var nestedKeyAnyValue = ReadProtobufFields(nestedEntries["nestedKey"].Data);
                Assert.Equal(1, nestedKeyAnyValue[0].FieldNumber);
                Assert.Equal("nestedValue", Encoding.UTF8.GetString(nestedKeyAnyValue[0].Data));

                // nestedInt should be int_value (AnyValue field 3)
                var nestedIntAnyValue = ReadProtobufFields(nestedEntries["nestedInt"].Data);
                Assert.Equal(3, nestedIntAnyValue[0].FieldNumber);
                Assert.Equal(0, nestedIntAnyValue[0].WireType);
            }
        }

        [Fact]
        public void PostSingleMessage_ListProperty_EncodedAsArrayAnyValue()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = true,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "list prop");
                    logEvent.Properties["ListProp"] = new List<object> { "alpha", 99, true };
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord attributes
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // Find the ListProp attribute
                var attributes = logRecord.FindAll(f => f.FieldNumber == 6);
                ProtobufField listAnyValue = default;
                for (int i = 0; i < attributes.Count; i++)
                {
                    var kvFields = ReadProtobufFields(attributes[i].Data);
                    var keyField = kvFields.Find(f => f.FieldNumber == 1);
                    if (Encoding.UTF8.GetString(keyField.Data) == "ListProp")
                    {
                        listAnyValue = kvFields.Find(f => f.FieldNumber == 2);
                        break;
                    }
                }
                Assert.True(listAnyValue.Data.Length > 0, "ListProp attribute should be present");

                // AnyValue field 5 = array_value (wire type 2, length-delimited)
                var anyValueFields = ReadProtobufFields(listAnyValue.Data);
                var arrayField = anyValueFields.Find(f => f.FieldNumber == 5);
                Assert.Equal(2, arrayField.WireType);

                // ArrayValue { repeated AnyValue values = 1 }
                var arrayEntries = ReadProtobufFields(arrayField.Data);
                Assert.Equal(3, arrayEntries.Count);

                // Element 0: "alpha" → string_value (AnyValue field 1)
                var elem0 = ReadProtobufFields(arrayEntries[0].Data);
                Assert.Equal(1, elem0[0].FieldNumber);
                Assert.Equal("alpha", Encoding.UTF8.GetString(elem0[0].Data));

                // Element 1: 99 → int_value (AnyValue field 3)
                var elem1 = ReadProtobufFields(arrayEntries[1].Data);
                Assert.Equal(3, elem1[0].FieldNumber);
                Assert.Equal(0, elem1[0].WireType);

                // Element 2: true → bool_value (AnyValue field 2)
                var elem2 = ReadProtobufFields(arrayEntries[2].Data);
                Assert.Equal(2, elem2[0].FieldNumber);
                Assert.Equal(0, elem2[0].WireType);
            }
        }

        [Fact]
        public void PostSingleMessage_ExcludesEventPropertiesWhenDisabled()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    IncludeEventProperties = false,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    var logEvent = new LogEventInfo(LogLevel.Info, "TestLogger", "no props");
                    logEvent.Properties["SecretKey"] = "SecretValue";
                    logger.Log(logEvent);
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.DoesNotContain("SecretKey", bodyText);
                Assert.DoesNotContain("SecretValue", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_IncludesExceptionAttributes()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Error(new InvalidOperationException("test exception"), "error occurred");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("exception.type", bodyText);
                Assert.Contains("InvalidOperationException", bodyText);
                Assert.Contains("exception.message", bodyText);
                Assert.Contains("test exception", bodyText);
            }
        }

        [Fact]
        public void PostSingleMessage_IncludesResourceAttributes()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ServiceName = "MySvc",
                };
                target.ResourceAttributes.Add(new TargetPropertyWithContext { Name = "deployment.environment", Layout = "staging" });

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("resource test");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                Assert.Contains("MySvc", bodyText);
                Assert.Contains("deployment.environment", bodyText);
                Assert.Contains("staging", bodyText);
            }
        }

        [Fact]
        public void BatchMessages_SentAsSingleRequest()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    BatchSize = 200,
                    TaskDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("batch1");
                    logger.Info("batch2");
                    logger.Info("batch3");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.True(requests.Count >= 1);

                // All messages should be in the protobuf payload(s)
                var allBodyText = new StringBuilder();
                foreach (var req in requests)
                    allBodyText.Append(Encoding.UTF8.GetString(req.BodyBytes));

                var combined = allBodyText.ToString();
                Assert.Contains("batch1", combined);
                Assert.Contains("batch2", combined);
                Assert.Contains("batch3", combined);
            }
        }

        [Fact]
        public void GZipCompression_CompressesPayloadAndSetsHeader()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    Compress = HttpCompressionType.GZip,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("compressed otlp message");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.True(requests[0].Headers.TryGetValue("Content-Encoding", out var encoding));
                Assert.Equal("gzip", encoding);

                var decompressed = DecompressGzip(requests[0].BodyBytes);
                Assert.Contains("compressed otlp message", decompressed);
            }
        }

        [Fact]
        public void ProtobufPayload_HasValidStructure()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ServiceName = "StructTest",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("structure test");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Parse the top-level ExportLogsServiceRequest
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                Assert.True(topFields.Count >= 1, "ExportLogsServiceRequest should have at least 1 field (resource_logs)");

                // Field 1 = ResourceLogs (wire type 2 = length-delimited)
                var resourceLogsField = topFields.Find(f => f.FieldNumber == 1);
                Assert.Equal(2, resourceLogsField.WireType);

                // Parse ResourceLogs
                var rlFields = ReadProtobufFields(resourceLogsField.Data);
                Assert.True(rlFields.Count >= 2, "ResourceLogs should have resource and scope_logs");

                // Field 1 = Resource, Field 2 = ScopeLogs
                var resourceField = rlFields.Find(f => f.FieldNumber == 1);
                Assert.Equal(2, resourceField.WireType);
                var scopeLogsField = rlFields.Find(f => f.FieldNumber == 2);
                Assert.Equal(2, scopeLogsField.WireType);

                // Parse ScopeLogs and verify it has log_records (field 2)
                var slFields = ReadProtobufFields(scopeLogsField.Data);
                var logRecordField = slFields.Find(f => f.FieldNumber == 2);
                Assert.NotNull(logRecordField.Data);
                Assert.True(logRecordField.Data.Length > 0, "LogRecord should have content");

                // Parse LogRecord and verify timestamp (field 1, fixed64) exists
                var lrFields = ReadProtobufFields(logRecordField.Data);
                var timestampField = lrFields.Find(f => f.FieldNumber == 1);
                Assert.Equal(1, timestampField.WireType); // fixed64
                Assert.Equal(8, timestampField.Data.Length);
            }
        }

        [Fact]
        public void TraceIdAndSpanId_EncodedAsBytesInLogRecord()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    TraceId = NLog.Layouts.Layout<System.Diagnostics.ActivityTraceId?>.FromMethod(l => System.Diagnostics.ActivityTraceId.CreateFromString("0af7651916cd43dd8448eb211c80319c".AsSpan())),
                    SpanId = NLog.Layouts.Layout<System.Diagnostics.ActivitySpanId?>.FromMethod(l => System.Diagnostics.ActivitySpanId.CreateFromString("b7ad6b7169203331".AsSpan())),
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("trace context test");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // trace_id = field 9, bytes (wire type 2), 16 bytes
                var traceIdField = logRecord.Find(f => f.FieldNumber == 9);
                Assert.Equal(2, traceIdField.WireType);
                Assert.Equal(16, traceIdField.Data.Length);
                Assert.Equal("0af7651916cd43dd8448eb211c80319c", BitConverter.ToString(traceIdField.Data).Replace("-", "").ToLowerInvariant());

                // span_id = field 10, bytes (wire type 2), 8 bytes
                var spanIdField = logRecord.Find(f => f.FieldNumber == 10);
                Assert.Equal(2, spanIdField.WireType);
                Assert.Equal(8, spanIdField.Data.Length);
                Assert.Equal("b7ad6b7169203331", BitConverter.ToString(spanIdField.Data).Replace("-", "").ToLowerInvariant());
            }
        }

        [Fact]
        public void TraceIdAndSpanId_OmittedWhenEmpty()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    TraceId = "",
                    SpanId = "",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("no trace context");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Navigate to LogRecord
                var topFields = ReadProtobufFields(requests[0].BodyBytes);
                var resourceLogs = ReadProtobufFields(topFields.Find(f => f.FieldNumber == 1).Data);
                var scopeLogs = ReadProtobufFields(resourceLogs.Find(f => f.FieldNumber == 2).Data);
                var logRecord = ReadProtobufFields(scopeLogs.Find(f => f.FieldNumber == 2).Data);

                // No trace_id (field 9) or span_id (field 10) should be present
                Assert.DoesNotContain(logRecord, f => f.FieldNumber == 9);
                Assert.DoesNotContain(logRecord, f => f.FieldNumber == 10);
            }
        }

        [Fact]
        public void MultipleLogEvents_ShareSameServiceName()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    ServiceName = "TestService"
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");

                    logger.Info("event-1");
                    logger.Info("event-2");
                    logger.Info("event-3");

                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                // Decode ExportLogsServiceRequest
                var topFields = ReadProtobufFields(requests[0].BodyBytes);

                // ResourceLogs (field 1)
                var resourceLogs = ReadProtobufFields(
                    topFields.Find(f => f.FieldNumber == 1).Data);

                // Resource (field 1 inside ResourceLogs)
                var resourceFields = ReadProtobufFields(
                    resourceLogs.Find(f => f.FieldNumber == 1).Data);

                // Parse KeyValue list into dictionary
                var attributes = ParseKeyValueList(resourceFields);

                // Get value container
                var valueField = attributes["service.name"];

                // Decode inner StringValue message
                var valueFields = ReadProtobufFields(valueField.Data);

                // StringValue is field 1
                var stringValueField = valueFields.Find(f => f.FieldNumber == 1);

                var serviceName = Encoding.UTF8.GetString(stringValueField.Data);
                Assert.Equal("TestService", serviceName);

                // Verify multiple log records exist in batch
                var scopeLogs = ReadProtobufFields(
                    resourceLogs.Find(f => f.FieldNumber == 2).Data);

                var logRecords = scopeLogs
                    .Where(f => f.FieldNumber == 2)
                    .ToList();

                Assert.True(logRecords.Count >= 3);
            }
        }

        [Fact]
        public void OtlpEndpointEnvVar_UsedAsUrlWhenNotExplicitlySet()
        {
            using (var server = new SimpleHttpServer())
            {
                var envEndpoint = $"http://127.0.0.1:{server.Port}";
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", envEndpoint);
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("env endpoint test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    Assert.Equal("/v1/logs", requests[0].Path);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
                }
            }
        }

        [Fact]
        public void OtlpLogsEndpointEnvVar_TakesPrecedenceOverGenericEndpoint()
        {
            using (var server = new SimpleHttpServer())
            {
                var logsEndpoint = $"http://127.0.0.1:{server.Port}/custom/logs";
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9999");
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", logsEndpoint);
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("logs endpoint test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    Assert.Equal("/custom/logs", requests[0].Path);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT", null);
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", null);
                }
            }
        }

        [Fact]
        public void OtlpHeadersEnvVar_ParsedAndSentInRequest()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer token123,X-Env-Header=envvalue");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("headers env test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    Assert.True(requests[0].Headers.TryGetValue("X-Env-Header", out var envHeader));
                    Assert.Equal("envvalue", envHeader);
                    Assert.True(requests[0].Headers.TryGetValue("Authorization", out var authHeader));
                    Assert.Equal("Bearer token123", authHeader);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_HEADERS", null);
                }
            }
        }

        [Fact]
        public void OtlpServiceNameEnvVar_UsedWhenNotExplicitlySet()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", "EnvServiceName");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("service name env test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                    Assert.Contains("EnvServiceName", bodyText);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", null);
                }
            }
        }

        [Fact]
        public void OtlpResourceAttributesEnvVar_ParsedIntoResourceAndServiceName()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_RESOURCE_ATTRIBUTES", "service.name=AttrService,deployment.environment=staging");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("resource attrs test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                    Assert.Contains("AttrService", bodyText);
                    Assert.Contains("deployment.environment", bodyText);
                    Assert.Contains("staging", bodyText);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_RESOURCE_ATTRIBUTES", null);
                }
            }
        }

        [Fact]
        public void OtlpServiceNameEnvVar_TakesPrecedenceOverResourceAttributes()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_RESOURCE_ATTRIBUTES", "service.name=FromAttrs");
                Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", "FromEnvVar");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("precedence test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                    Assert.Contains("FromEnvVar", bodyText);
                    Assert.DoesNotContain("FromAttrs", bodyText);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_RESOURCE_ATTRIBUTES", null);
                    Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", null);
                }
            }
        }

        [Fact]
        public void OtlpCompressionEnvVar_EnablesGzip()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                    };

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("compression env test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);
                    Assert.True(requests[0].Headers.TryGetValue("Content-Encoding", out var encoding));
                    Assert.Equal("gzip", encoding);

                    var decompressed = DecompressGzip(requests[0].BodyBytes);
                    Assert.Contains("compression env test", decompressed);
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_COMPRESSION", null);
                }
            }
        }

        [Fact]
        public void ExplicitConfig_TakesPrecedenceOverEnvVars()
        {
            using (var server = new SimpleHttpServer())
            {
                Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", "EnvService");
                Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_HEADERS", "X-Env=envvalue");
                try
                {
                    var target = new OpenTelemetryHttpTarget
                    {
                        Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                        Layout = "${message}",
                        ServiceName = "ExplicitService",
                    };
                    target.Headers.Add(new TargetPropertyWithContext { Name = "X-Explicit", Layout = "explicitvalue" });

                    using (var logFactory = BuildLogFactory(target))
                    {
                        var logger = logFactory.GetLogger("TestLogger");
                        logger.Info("precedence test");
                        logFactory.Flush();
                    }

                    var requests = server.WaitForRequests(1);
                    Assert.True(requests.Count >= 1);

                    // Explicit ServiceName should be used, not env var
                    var bodyText = Encoding.UTF8.GetString(requests[0].BodyBytes);
                    Assert.Contains("ExplicitService", bodyText);
                    Assert.DoesNotContain("EnvService", bodyText);

                    // Explicit headers should be used, env var headers should not be added
                    Assert.True(requests[0].Headers.TryGetValue("X-Explicit", out var explicitHeader));
                    Assert.Equal("explicitvalue", explicitHeader);
                    Assert.False(requests[0].Headers.ContainsKey("X-Env"));
                }
                finally
                {
                    Environment.SetEnvironmentVariable("OTEL_SERVICE_NAME", null);
                    Environment.SetEnvironmentVariable("OTEL_EXPORTER_OTLP_HEADERS", null);
                }
            }
        }

        private static LogFactory BuildLogFactory(OpenTelemetryHttpTarget target)
        {
            var logFactory = new LogFactory();
            var config = new LoggingConfiguration(logFactory);
            config.AddRuleForAllLevels(target);
            logFactory.Configuration = config;
            return logFactory;
        }

        private static string DecompressGzip(byte[] compressed)
        {
            using (var input = new MemoryStream(compressed))
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                gzip.CopyTo(output);
                return Encoding.UTF8.GetString(output.ToArray());
            }
        }

        #region Protobuf Reader Helpers

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
                    case 1: // 64-bit (fixed64)
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
                    case 5: // 32-bit (fixed32)
                        fieldData = new byte[4];
                        Array.Copy(data, offset, fieldData, 0, 4);
                        offset += 4;
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown protobuf wire type: {wireType}");
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

        #endregion

        private sealed class SimpleHttpServer : IDisposable
        {
            private readonly TcpListener _listener;
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();
            private readonly List<CapturedRequest> _requests = new List<CapturedRequest>();
            private readonly object _lock = new object();
            private readonly SemaphoreSlim _requestSignal = new SemaphoreSlim(0);

            public int ResponseStatusCode { get; set; } = 200;

            public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

            public SimpleHttpServer()
            {
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
                Task.Run(AcceptLoopAsync, _cts.Token);
            }

            public List<CapturedRequest> WaitForRequests(int count, int timeoutMs = 15000)
            {
                if (timeoutMs > 1 && Debugger.IsAttached)
                    timeoutMs = 120000;

                var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                while (DateTime.UtcNow < deadline)
                {
                    lock (_lock)
                    {
                        if (_requests.Count >= count)
                            return new List<CapturedRequest>(_requests);
                    }
                    _requestSignal.Wait(50);
                }
                lock (_lock)
                    return new List<CapturedRequest>(_requests);
            }

            private async Task AcceptLoopAsync()
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        _ = Task.Run(() => HandleClientAsync(client), _cts.Token);
                    }
                    catch
                    {
                        break;
                    }
                }
            }

            private async Task HandleClientAsync(TcpClient client)
            {
                using (client)
                {
                    var stream = client.GetStream();
                    var request = await ReadHttpRequestAsync(stream, _cts.Token).ConfigureAwait(false);
                    lock (_lock)
                        _requests.Add(request);
                    _requestSignal.Release();

                    var statusLine = ResponseStatusCode == 200 ? "200 OK" : $"{ResponseStatusCode} Error";
                    var response = $"HTTP/1.1 {statusLine}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    var responseBytes = Encoding.ASCII.GetBytes(response);
                    await stream.WriteAsync(responseBytes, 0, responseBytes.Length, _cts.Token).ConfigureAwait(false);
                }
            }

            private static async Task<CapturedRequest> ReadHttpRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
            {
                var headerBytes = new List<byte>(512);
                while (true)
                {
                    var b = stream.ReadByte();
                    if (b == -1) break;
                    headerBytes.Add((byte)b);
                    var n = headerBytes.Count;
                    if (n >= 4
                        && headerBytes[n - 4] == '\r'
                        && headerBytes[n - 3] == '\n'
                        && headerBytes[n - 2] == '\r'
                        && headerBytes[n - 1] == '\n')
                    {
                        break;
                    }
                }

                var headerText = Encoding.ASCII.GetString(headerBytes.ToArray());
                var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);

                var requestParts = lines.Length > 0 ? lines[0].Split(' ') : new string[0];
                var method = requestParts.Length > 0 ? requestParts[0] : string.Empty;
                var path = requestParts.Length > 1 ? requestParts[1] : string.Empty;

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 1; i < lines.Length; i++)
                {
                    var colonIdx = lines[i].IndexOf(':');
                    if (colonIdx > 0)
                        headers[lines[i].Substring(0, colonIdx).Trim()] = lines[i].Substring(colonIdx + 1).Trim();
                }

                var bodyBytes = new byte[0];
                if (headers.TryGetValue("Content-Length", out var contentLengthStr)
                    && int.TryParse(contentLengthStr, out var contentLength)
                    && contentLength > 0)
                {
                    bodyBytes = new byte[contentLength];
                    int bytesRead = 0;
                    while (bytesRead < contentLength)
                    {
                        var read = await stream.ReadAsync(bodyBytes, bytesRead, contentLength - bytesRead, cancellationToken).ConfigureAwait(false);
                        if (read == 0) break;
                        bytesRead += read;
                    }
                }

                return new CapturedRequest
                {
                    Method = method,
                    Path = path,
                    Headers = headers,
                    BodyBytes = bodyBytes,
                    Body = Encoding.UTF8.GetString(bodyBytes),
                };
            }

            public void Dispose()
            {
                _cts.Cancel();
                _listener.Stop();
                _requestSignal.Dispose();
                _cts.Dispose();
            }
        }

        private sealed class CapturedRequest
        {
            public string Method { get; set; } = string.Empty;
            public string Path { get; set; } = string.Empty;
            public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public byte[] BodyBytes { get; set; } = new byte[0];
            public string Body { get; set; } = string.Empty;
        }
    }
}
