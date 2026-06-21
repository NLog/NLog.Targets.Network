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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var logFields = logRecord.AsMessage();
                var bodyValue = logFields.GetField(5).AsAnyValueString();
                Assert.Equal("hello otlp world", bodyValue);

                var logAttributes = logFields.GetFieldValues(6);
                Assert.Equal("TestLogger", logAttributes["logger.name"].AsAnyValueString());

                var resourceAttributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                Assert.Equal("TestService", resourceAttributes["service.name"].AsAnyValueString());
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var logFields = logRecord.AsMessage();
                var bodyValue = logFields.GetField(5).AsAnyValueString();
                Assert.Equal("warning message", bodyValue);

                var severityField = logFields.GetField(3).AsString();
                Assert.Equal("Warn", severityField);
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


                var scopeLogs = ProtobufParser.GetScopeLogs(requests[0].BodyBytes);

                var scopeName = scopeLogs
                    .GetField(1)   // InstrumentationScope
                    .GetField(1)   // name
                    .AsString();

                Assert.Equal("MyInstrumentationScope", scopeName);
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

                var attributes = ProtobufParser.GetLogRecord(requests[0].BodyBytes).AsMessage().GetFieldValues(6);
                Assert.Equal("CustomValue", attributes["CustomKey"].AsAnyValueString());
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var logAttributes = logRecord.AsMessage().GetFieldValues(6);

                Assert.Equal(1, logAttributes["BoolProp"].AsAnyValue().AsInt64());
                Assert.Equal(42, logAttributes["IntProp"].AsAnyValue().AsInt64());
                Assert.Equal(3.14, logAttributes["DoubleProp"].AsAnyValue().AsDouble());
                Assert.Equal("hello", logAttributes["StringProp"].AsAnyValue().AsString());
                Assert.Equal("Resume", logAttributes["EnumProp"].AsAnyValue().AsString());
            }
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var attributes = logRecord.AsMessage().GetFieldValues(6);

                var nan = attributes["NaNProp"].AsAnyValue().AsDouble();
                Assert.True(double.IsNaN(nan));

                var posInf = attributes["PosInfProp"].AsAnyValue().AsDouble();
                Assert.True(double.IsPositiveInfinity(posInf));

                var negInf = attributes["NegInfProp"].AsAnyValue().AsDouble();
                Assert.True(double.IsNegativeInfinity(negInf));

                var floatNaN = attributes["FloatNaNProp"].AsAnyValue().AsDouble();
                Assert.True(double.IsNaN(floatNaN));
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var attributes = logRecord.AsMessage().GetFieldValues(6);

                var kvList = attributes["MapProp"].AsAnyValue().AsMessage();

                var map = kvList.GetFieldValues(1);

                // nestedKey → string_value
                Assert.Equal("nestedValue", map["nestedKey"].AsAnyValue().AsString());

                // nestedInt → int_value
                Assert.Equal(42, map["nestedInt"].AsAnyValue().AsInt64());
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var attributes = logRecord.AsMessage().GetFieldValues(6);

                // AnyValue.array_value = field 5
                var listAnyValue = attributes["ListProp"].AsAnyValue();
                Assert.Equal(5, listAnyValue.FieldNumber);
                var arrayEntries = listAnyValue.AsMessage();

                Assert.Equal(3, arrayEntries.Count);
                Assert.Equal("alpha", arrayEntries[0].AsMessage().GetField(1).AsString());
                Assert.Equal(99, arrayEntries[1].AsMessage().GetField(3).AsInt64());
                Assert.Equal(1, arrayEntries[2].AsMessage().GetField(2).AsInt64());
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var attributes = logRecord.AsMessage().GetFieldValues(6);
                Assert.False(attributes.ContainsKey("SecretKey"));
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var attributes = logRecord.AsMessage().GetFieldValues(6);
                Assert.Equal(typeof(InvalidOperationException).ToString(), attributes["exception.type"].AsAnyValueString());
                Assert.Equal("test exception", attributes["exception.message"].AsAnyValueString());
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes).AsMessage();
                Assert.NotEmpty(logRecord);

                var attributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                Assert.Equal("MySvc", attributes["service.name"].AsAnyValueString());
                Assert.Equal("staging", attributes["deployment.environment"].AsAnyValueString());
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

                var allLogRecords = new List<ProtobufParser.ProtobufField>();
                foreach (var req in requests)
                {
                    var records = ProtobufParser.GetLogRecords(req.BodyBytes);
                    allLogRecords.AddRange(records);
                }

                // Ensure batching preserved all events
                Assert.True(allLogRecords.Count >= 3);

                // Validate payload content
                var messages = allLogRecords
                    .Select(r =>
                    {
                        var fields = r.AsMessage();

                        // body = field 5 → AnyValue → string_value (field 1)
                        var body = fields.GetField(5).AsMessage().GetField(1);
                        return body.AsString();
                    })
                    .ToList();

                Assert.Contains("batch1", messages);
                Assert.Contains("batch2", messages);
                Assert.Contains("batch3", messages);
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

                var decompressedBytes = DecompressGzip(requests[0].BodyBytes);
                var logRecord = ProtobufParser.GetLogRecord(decompressedBytes);
                var body = logRecord.AsMessage().GetField(5).GetField(1).AsString();
                Assert.Equal("compressed otlp message", body);
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);

                // timestamp (field 1, fixed64)
                var timestamp = logRecord.AsMessage().GetField(1);
                Assert.Equal(1, timestamp.WireType);
                Assert.Equal(8, timestamp.Data.Length);

                // body (field 5 → AnyValue → string_value field 1)
                var body = logRecord.AsMessage().GetField(5);
                var bodyValue = body.AsMessage().GetField(1);
                Assert.Equal("structure test", bodyValue.AsString());
            }
        }

        [Fact]
        public void TraceIdAndSpanId_EncodedAsBytesInLogRecord()
        {
            const string expectedTraceId = "0af7651916cd43dd8448eb211c80319c";
            const string expectedSpanId = "b7ad6b7169203331";

            using (var server = new SimpleHttpServer())
            {
                var target = new OpenTelemetryHttpTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/v1/logs",
                    Layout = "${message}",
                    TraceId = NLog.Layouts.Layout<System.Diagnostics.ActivityTraceId?>.FromMethod(l => System.Diagnostics.ActivityTraceId.CreateFromString(expectedTraceId.AsSpan())),
                    SpanId = NLog.Layouts.Layout<System.Diagnostics.ActivitySpanId?>.FromMethod(l => System.Diagnostics.ActivitySpanId.CreateFromString(expectedSpanId.AsSpan())),
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("trace context test");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var fields = logRecord.AsMessage();

                // trace_id = field 9 (bytes, 16 bytes)
                var traceId = fields.GetField(9);
                Assert.Equal(2, traceId.WireType);
                Assert.Equal(16, traceId.Data.Length);
                Assert.Equal(expectedTraceId, ToHex(traceId.Data));

                // span_id = field 10 (bytes, 8 bytes)
                var spanId = fields.GetField(10);
                Assert.Equal(2, spanId.WireType);
                Assert.Equal(8, spanId.Data.Length);
                Assert.Equal(expectedSpanId, ToHex(spanId.Data));
            }
        }

        private static string ToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
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

                var logRecord = ProtobufParser.GetLogRecord(requests[0].BodyBytes);
                var fields = logRecord.AsMessage();
                Assert.NotEmpty(fields);

                // trace_id (field 9) and span_id (field 10) must not be present
                Assert.DoesNotContain(fields, f => f.FieldNumber == 9);
                Assert.DoesNotContain(fields, f => f.FieldNumber == 10);
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

                var resourceAttributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                Assert.Equal("TestService", resourceAttributes["service.name"].AsAnyValueString());

                // Verify multiple log records exist in batch
                var logRecords = ProtobufParser.GetLogRecords(requests[0].BodyBytes);
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
                    Assert.Single(requests);
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
                    Assert.Single(requests);
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
                    Assert.Single(requests);

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
                    Assert.Single(requests);

                    var resourceAttributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                    Assert.Equal("EnvServiceName", resourceAttributes["service.name"].AsAnyValueString());  
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
                    Assert.Single(requests);

                    var resourceAttributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                    Assert.Equal("AttrService", resourceAttributes["service.name"].AsAnyValueString());
                    Assert.Equal("staging", resourceAttributes["deployment.environment"].AsAnyValueString());
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
                    Assert.Single(requests);

                    var resourceAttributes = ProtobufParser.GetResourceAttributes(requests[0].BodyBytes);
                    Assert.Equal("FromEnvVar", resourceAttributes["service.name"].AsAnyValueString());
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
                    Assert.Single(requests);
                    Assert.True(requests[0].Headers.TryGetValue("Content-Encoding", out var encoding));
                    Assert.Equal("gzip", encoding);

                    var decompressedBytes = DecompressGzip(requests[0].BodyBytes);
                    var logRecord = ProtobufParser.GetLogRecord(decompressedBytes);
                    var body = logRecord.AsMessage().GetField(5).GetField(1).AsString();
                    Assert.Equal("compression env test", body);
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
                    Assert.Single(requests);

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

        private static byte[] DecompressGzip(byte[] compressed)
        {
            using (var input = new MemoryStream(compressed))
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                gzip.CopyTo(output);
                return output.ToArray();
            }
        }

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
