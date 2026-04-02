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

#if !NET35

namespace NLog.Targets.Network
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.IO.Compression;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using NLog.Config;
    using Xunit;

    public class HttpClientTargetTests
    {
        public HttpClientTargetTests()
        {
            LogManager.ThrowExceptions = true;
        }

        [Fact]
        public void PostSingleMessage_HappyPath()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${logger}|${message}",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello world");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.Equal("POST", requests[0].Method);
                Assert.Equal("/logs", requests[0].Path);
                Assert.Equal("TestLogger|hello world", requests[0].Body);
            }
        }

#if !NETFRAMEWORK
        [Fact]
        public void GetRequest_SendsCorrectMethod()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    HttpMethod = "Get",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.Equal("GET", requests[0].Method);
            }
        }
#endif

        [Fact]
        public void BatchMessages_JoinedWithNewline()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    TaskDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("msg1");
                    logger.Info("msg2");
                    logger.Info("msg3");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.True(requests.Count >= 1);
                var allBodies = string.Concat(requests.ConvertAll(r => r.Body));
                Assert.Contains("msg1", allBodies);
                Assert.Contains("msg2", allBodies);
                Assert.Contains("msg3", allBodies);
            }
        }

        [Fact]
        public void BatchAsJsonArray_WrapsMessagesInArray()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    BatchAsJsonArray = true,
                    BatchSize = 200,
                    TaskDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("msg1");
                    logger.Info("msg2");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.True(requests.Count >= 1);
                Assert.Equal("[msg1, msg2]", requests[0].Body);
            }
        }

        [Fact]
        public void ContentType_CustomValue_IsReflectedInHeader()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    ContentType = "text/plain",
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.True(requests[0].Headers.TryGetValue("Content-Type", out var ctValue));
                Assert.Contains("text/plain", ctValue);
            }
        }

        [Fact]
        public void GZipCompression_CompressesPayloadAndSetsHeader()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    Compress = NetworkTargetCompressionType.GZip,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("compressed message");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.True(requests[0].Headers.TryGetValue("Content-Encoding", out var encoding));
                Assert.Equal("gzip", encoding);
                var decompressed = DecompressGzip(requests[0].BodyBytes);
                Assert.Equal("compressed message", decompressed);
            }
        }

        [Fact]
        public void CustomHeaders_AreSentInRequest()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                };
                target.Headers.Add(new TargetPropertyWithContext { Name = "Authorization", Layout = "Bearer mytoken123" });
                target.Headers.Add(new TargetPropertyWithContext { Name = "X-Custom-Header", Layout = "custom-value" });

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
                Assert.True(requests[0].Headers.TryGetValue("X-Custom-Header", out var customHeader));
                Assert.Equal("custom-value", customHeader);
                Assert.True(requests[0].Headers.TryGetValue("Authorization", out var authorizationHeader));
                Assert.Equal("Bearer mytoken123", authorizationHeader);
            }
        }

        [Fact]
        public void MaxPayloadSizeBytes_SplitsLargeBatchIntoMultipleRequests()
        {
            using (var server = new SimpleHttpServer())
            {
                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    MaxPayloadSizeBytes = 5,    // Forces split: each ~4-byte message overflows with separator
                    RetryCount = 0,
                    TaskDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("msg1");
                    logger.Info("msg2");
                    logger.Info("msg3");
                    logFactory.Flush();
                }

                var requests = server.WaitForRequests(2);
                Assert.True(requests.Count >= 2, $"Expected at least 2 batched requests, got {requests.Count}");
                var allBodies = string.Concat(requests.ConvertAll(r => r.Body));
                Assert.Contains("msg1", allBodies);
                Assert.Contains("msg2", allBodies);
                Assert.Contains("msg3", allBodies);
            }
        }

        [Fact]
        public void ServerError5xx_TriggersRetry()
        {
            using (var server = new SimpleHttpServer())
            {
                server.ResponseStatusCode = 500;

                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    RetryCount = 1,
                    RetryDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    logFactory.ThrowExceptions = false;
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello");
                    logFactory.Flush();
                }

                // 1 initial attempt + 1 retry = 2 total requests
                var requests = server.WaitForRequests(2);
                Assert.Equal(2, requests.Count);
            }
        }

        [Fact]
        public void Server4xx_DoesNotRetry()
        {
            using (var server = new SimpleHttpServer())
            {
                server.ResponseStatusCode = 400;

                var target = new HttpClientTarget
                {
                    Url = $"http://127.0.0.1:{server.Port}/logs",
                    Layout = "${message}",
                    RetryCount = 3,
                    RetryDelayMilliseconds = 10,
                };

                using (var logFactory = BuildLogFactory(target))
                {
                    logFactory.ThrowExceptions = false;
                    var logger = logFactory.GetLogger("TestLogger");
                    logger.Info("hello");
                    logFactory.Flush();
                }

                // 400 is not retried, so only 1 request
                var requests = server.WaitForRequests(1);
                Assert.Single(requests);
            }
        }

        private static LogFactory BuildLogFactory(HttpClientTarget target)
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
            using (var reader = new StreamReader(gzip, Encoding.UTF8))
            {
                return reader.ReadToEnd();
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
                    timeoutMs = 120000; // Allow more time when debugging

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
                // Read headers byte by byte until the end-of-headers marker (\r\n\r\n)
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

                // Read the body according to Content-Length
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

#endif
