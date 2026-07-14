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
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using NLog.Config;
    using NLog.Layouts;

    /// <summary>
    /// Sends log events to an HTTP or HTTPS endpoint, with support for batching and compression.
    /// </summary>
    /// <remarks>
    /// <a href="https://github.com/NLog/NLog/wiki/HttpClient-target">See NLog Wiki</a>
    /// </remarks>
    /// <seealso href="https://github.com/NLog/NLog/wiki/HttpClient-target">Documentation on NLog Wiki</seealso>
    [Target("HttpClient")]
    [Target("Http")]
    public class HttpClientTarget : AsyncTaskTarget
    {
        private static readonly Encoding _utf8Encoding = new UTF8Encoding(false);   // No PreAmble BOM
        private readonly char[] _reusableEncodingBuffer = new char[40 * 1024];  // Avoid large-object-heap
        private readonly StringBuilder _reusableEncodingBuilder = new StringBuilder();
        private readonly Stack<MemoryStream> _memoryStreamPool = new Stack<MemoryStream>();
        private volatile HttpClient? _httpClient;
        private const int _httpClientLifeTimeTicks = 5 * 60 * 1000;
        private volatile int _httpClientCreatedTicks = 0;
#if !NETFRAMEWORK || NET471_OR_GREATER
        private readonly NLog.Internal.SslCertificateCache _sslCertificateCache = new NLog.Internal.SslCertificateCache();
#endif

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpClientTarget"/> class with default settings.
        /// </summary>
        public HttpClientTarget()
        {
            RetryDelayMilliseconds = 2500;  // Delay before retry when transient failures. Ex Rate-Limited responses (e.g. HTTP 429)
        }

        /// <summary>
        /// Gets or sets the EndPoint destination URL for HTTP requests.
        /// </summary>
        public Layout Url
        {
            get => _url;
            set
            {
                if (ReferenceEquals(value, _url)) return;
                _url = value;
                SignalHttpClientReset();
            }
        }
        private Layout _url = Layout.Empty;

        /// <summary>
        /// Gets or sets the HTTP method used for the request.
        /// </summary>
        /// <remarks>Default: <see langword="Post"/></remarks>
        public string HttpMethod
        {
            get => _httpMethod.ToString();
            set
            {
                var httpMethod = value?.Trim() ?? string.Empty;
                if (string.Equals(httpMethod, nameof(System.Net.Http.HttpMethod.Post), StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(httpMethod))
                    _httpMethod = System.Net.Http.HttpMethod.Post;
                else if (string.Equals(httpMethod, nameof(System.Net.Http.HttpMethod.Get), StringComparison.OrdinalIgnoreCase))
                    _httpMethod = System.Net.Http.HttpMethod.Get;
                else
                    _httpMethod = new System.Net.Http.HttpMethod(httpMethod.ToUpperInvariant());
            }
        }
        private System.Net.Http.HttpMethod _httpMethod = System.Net.Http.HttpMethod.Post;

        /// <summary>
        /// Get or sets the content-type header to use for the http-request.
        /// </summary>
        /// <remarks>Default: <c>application/json</c></remarks>
        public string ContentType
        {
            get => _contentType;
            set
            {
                if (value == _contentType) return;
                _contentType = string.IsNullOrWhiteSpace(value) ? "application/json" : value;
                var isTextContentType = _contentType.IndexOf("text", StringComparison.OrdinalIgnoreCase) >= 0 || _contentType.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0 || _contentType.IndexOf("xml", StringComparison.OrdinalIgnoreCase) >= 0;
                _contentTypeHeader = new MediaTypeHeaderValue(_contentType) { CharSet = isTextContentType ? _utf8Encoding.WebName : null };
            }
        }
        private string _contentType = "application/json";
        private MediaTypeHeaderValue _contentTypeHeader = new MediaTypeHeaderValue("application/json") { CharSet = _utf8Encoding.WebName };

        /// <summary>
        /// Gets or sets whether HTTP persistent connections (Keep-Alive) are enabled.
        /// </summary>
        /// <remarks>Default: <see langword="true"/></remarks>
        public bool KeepAlive
        {
            get => _keepAlive;
            set
            {
                if (value == _keepAlive) return;
                _keepAlive = value;
                SignalHttpClientReset();
            }
        }
        private bool _keepAlive = true;

        /// <summary>
        /// Get or sets whether to expect http 100-Continue behavior, where the client sends headers and expects the http-server to reply with http-status 100-continue before sending the http-request body.
        ///
        /// This can introduce additional latency for the http-request, especially when http-server does not support the protocol.
        /// </summary>
        public bool? Expect100Continue
        {
            get => _expect100Continue;
            set
            {
                if (value == _expect100Continue) return;
                _expect100Continue = value;
                SignalHttpClientReset();
            }
        }
        private bool? _expect100Continue
#if NETFRAMEWORK
            = false
#endif
            ;

        /// <summary>
        /// Gets or sets the line ending mode to use when batching log events.
        /// </summary>
        /// <remarks>Remember to assign <see cref="AsyncTaskTarget.BatchSize"/> to enable batching. Has no effect when using <see cref="BatchAsJsonArray"/> = <see langword="true"/></remarks>
        public LineEndingMode LineEnding { get; set; } = LineEndingMode.LF;

        /// <summary>
        /// Gets or sets whether batched log events are wrapped in a JSON array. (Overrides <see cref="LineEnding"/>)
        /// </summary>
        /// <remarks>Default: <see langword="false"/> (Remember to assign <see cref="AsyncTaskTarget.BatchSize"/> to enable batching)</remarks>
        public bool BatchAsJsonArray { get; set; }

        /// <summary>
        /// Gets or sets the timeout duration, in seconds, for HTTP requests.
        /// </summary>
        /// <remarks>Default: <see langword="30"/> secs</remarks>
        public int SendTimeoutSeconds
        {
            get => _sendTimeoutSeconds;
            set
            {
                if (value == _sendTimeoutSeconds) return;
                _sendTimeoutSeconds = value;
                SignalHttpClientReset();
            }
        }
        private int _sendTimeoutSeconds = 30;

        /// <summary>
        /// Gets or sets the <see cref="NetworkCredential"/> username used for HTTP authentication.
        /// </summary>
        /// <remarks>Explicit Empty/Blank String means use default network credentials (NTLM Windows Authentication)</remarks>
        public Layout? NetworkUserName
        {
            get => _networkUserName;
            set
            {
                if (ReferenceEquals(value, _networkUserName)) return;
                _networkUserName = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _networkUserName;

        /// <summary>
        /// Gets or sets the <see cref="NetworkCredential"/> password used for HTTP authentication.
        /// </summary>
        /// <remarks>Empty/Blank String means use default credentials</remarks>
        public Layout? NetworkPassword
        {
            get => _networkPassword;
            set
            {
                if (ReferenceEquals(value, _networkPassword)) return;
                _networkPassword = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _networkPassword;

#if !NETFRAMEWORK || NET471_OR_GREATER
        /// <summary>
        /// Gets or sets the file path to a client SSL certificate for mutual TLS (mTLS) authentication.
        /// </summary>
        public Layout? SslCertificateFile
        {
            get => _sslCertificateFile;
            set
            {
                if (ReferenceEquals(value, _sslCertificateFile)) return;
                _sslCertificateFile = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _sslCertificateFile;

        /// <summary>
        /// Gets or sets the password for the client SSL certificate specified by <see cref="SslCertificateFile"/>.
        /// </summary>
        public Layout? SslCertificatePassword
        {
            get => _sslCertificatePassword;
            set
            {
                if (ReferenceEquals(value, _sslCertificatePassword)) return;
                _sslCertificatePassword = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _sslCertificatePassword;
#endif

        /// <summary>
        /// Gets or sets the maximum payload size (in bytes) before batched log events are split into multiple HTTP payloads.
        /// </summary>
        /// <remarks>Default: <see langword="40960"/> bytes. Remember to assign <see cref="AsyncTaskTarget.BatchSize"/> to enable batching.</remarks>
        public int MaxPayloadSizeBytes { get; set; } = 40 * 1024;

        /// <summary>
        /// Gets or sets the compression mode used for HTTP request payloads. (None / GZip / GZipFast)
        /// </summary>
        /// <remarks>Default: <see langword="None"/></remarks>
        public HttpCompressionType Compress { get; set; }

        /// <summary>
        /// Gets or sets the collection of header properties to be included in the http-request.
        /// </summary>
        [ArrayParameter(typeof(TargetPropertyWithContext), "header")]
        public IList<TargetPropertyWithContext> Headers { get; set; } = new List<TargetPropertyWithContext>();

        /// <summary>
        /// Gets or sets the URL of the proxy server used for HTTP requests.
        /// </summary>
        /// <remarks>Explicit Empty/Blank String means default proxy</remarks>
        public Layout? ProxyUrl
        {
            get => _proxyUrl;
            set
            {
                if (ReferenceEquals(value, _proxyUrl)) return;
                _proxyUrl = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _proxyUrl;

        /// <summary>
        /// Gets or sets the username used when authenticating with the proxy server.
        /// </summary>
        public Layout? ProxyUser
        {
            get => _proxyUser;
            set
            {
                if (ReferenceEquals(value, _proxyUser)) return;
                _proxyUser = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _proxyUser;

        /// <summary>
        /// Gets or sets the password used when authenticating with the proxy server.
        /// </summary>
        public Layout? ProxyPassword
        {
            get => _proxyPassword;
            set
            {
                if (ReferenceEquals(value, _proxyPassword)) return;
                _proxyPassword = value;
                SignalHttpClientReset();
            }
        }
        private Layout? _proxyPassword;

        /// <inheritdoc />
        protected override void InitializeTarget()
        {
            if (Url is null || ReferenceEquals(Url, Layout.Empty))
                throw new NLogConfigurationException($"{nameof(Url)} layout must be specified for {GetType()}");

            string baseUrl = Url?.Render(LogEventInfo.CreateNullEvent()) ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(baseUrl))
            {
                if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var _))
                    throw new NLogConfigurationException($"Invalid {nameof(Url)} specified for {GetType()}: {baseUrl}");
            }

            var proxyUrl = ProxyUrl?.Render(LogEventInfo.CreateNullEvent()) ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(proxyUrl))
            {
                if (!Uri.TryCreate(proxyUrl, UriKind.Absolute, out var _))
                    throw new NLogConfigurationException($"Invalid {nameof(ProxyUrl)} specified for {GetType()}: {proxyUrl}");
            }

            base.InitializeTarget();
        }

        /// <inheritdoc />
        protected override void CloseTarget()
        {
            var oldHttpClient = _httpClient;
            _httpClient = null;
            _httpClientCreatedTicks = 0;
            oldHttpClient?.Dispose();
            base.CloseTarget();
        }

        /// <inheritdoc />
        protected sealed override Task WriteAsyncTask(LogEventInfo logEvent, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();  // Never called
        }

        /// <inheritdoc />
        protected override async Task WriteAsyncTask(IList<LogEventInfo> logEvents, CancellationToken cancellationToken)
        {
            int startIndex = 0;

            while (startIndex < logEvents.Count)
            {
                IList<LogEventInfo> batch = startIndex == 0
                    ? logEvents
                    : new LogEventBatch(logEvents, startIndex, logEvents.Count - startIndex);

                var output = RentMemoryStream();
                MemoryStream? compressed = null;

                try
                {
                    int consumed = SerializePayload(batch, output);
                    if (consumed <= 0)
                        throw new NLogRuntimeException($"{GetType().Name}.SerializePayload must consume at least one LogEventInfo.");

                    using (var httpContent = CreateHttpContent(output, out compressed))
                    {
                        var url = RenderBaseUrl(batch[0]);
                        await HttpClientSendAsync(url, httpContent, cancellationToken).ConfigureAwait(false);
                    }

                    startIndex += consumed;
                }
                finally
                {
                    ReturnMemoryStream(output);
                    if (compressed != null)
                    {
                        ReturnMemoryStream(compressed);
                    }
                }
            }
        }

        /// <summary>
        /// Send an HTTP request as an asynchronous operation.
        /// </summary>
        /// <remarks>Support custom <see cref="HttpClientTarget"/> overrides of WriteAsyncTask, that calls with custom ByteArrayContent / StreamContent</remarks>
        /// <param name="url">Override the default <see cref="HttpClient.BaseAddress"/></param>
        /// <param name="httpContent">The contents of the HTTP message</param>
        /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
        /// <returns>HTTP response with status-code and data (Remember to Dispose the response)</returns>
        protected async Task<HttpResponseMessage> HttpClientSendAsync(Uri? url, HttpContent httpContent, CancellationToken cancellationToken)
        {
            var httpClient = ResetHttpClientIfNeeded(url);

            HttpStatusCode httpStatusCode = default(HttpStatusCode);

            try
            {
                using var httpRequest = new HttpRequestMessage(_httpMethod, string.Empty) { Content = httpContent };
                httpRequest.Content.Headers.ContentType = _contentTypeHeader;

                var startTickCount = Environment.TickCount;

                var httpResponseMessage = await httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                httpStatusCode = httpResponseMessage.StatusCode;
                Common.InternalLogger.Debug("{0}: HTTP request completed after {1}ms with http-status-code {2}", this, (Environment.TickCount - startTickCount), (int)httpStatusCode);

                try
                {
                    httpResponseMessage.EnsureSuccessStatusCode();  // Throw if not a success code to trigger retry
                }
                catch (HttpRequestException ex)
                {
#if NET || NETSTANDARD2_1_OR_GREATER
                    if (httpStatusCode == HttpStatusCode.TooManyRequests || httpStatusCode == HttpStatusCode.RequestTimeout || ((int)httpStatusCode >= 500 && httpStatusCode != HttpStatusCode.NetworkAuthenticationRequired))
#else
                    if ((int)httpStatusCode == 429 || httpStatusCode == HttpStatusCode.RequestTimeout || ((int)httpStatusCode >= 500 && (int)httpStatusCode != 511))
#endif
                    {
                        // Retry 429 + 408 + 5xx (server errors, typically transient)
                        throw;
                    }

                    if (RetryCount <= 0)
                        throw;  // When no retry configured, then also re-throw the exception for non-transient errors for NLog AsyncContinuation reporting

                    // Swallow other failures (e.g. 400 Bad Request) without retrying
                    NLog.Common.InternalLogger.Error(ex, "{0}: HTTP request failed with status code {1}", this, (int)httpStatusCode);
                }
                return httpResponseMessage;
            }
            catch (Exception ex)
            {
                NLog.Common.InternalLogger.Error(ex, "{0}: HTTP request failed with status code {1}", this, (int)httpStatusCode);
                if (httpStatusCode == 0 && HttpClientLifeTimeExpired(Environment.TickCount, 5000))
                    SignalHttpClientReset();  // Reset HttpClient immediately on transport-level failures (e.g. DNS failure, network failure) to clear the stale HttpClient TCP connection pool.
                throw;
            }
        }

        /// <summary>
        /// Serializes log events into the HTTP request payload.
        /// </summary>
        /// <param name="logEvents">The log events to serialize.</param>
        /// <param name="output">The destination stream for the serialized payload. The stream is owned by <see cref="HttpClientTarget"/> and must not be disposed.</param>
        /// <returns>The number of log events consumed and serialized into the payload.</returns>
        protected virtual int SerializePayload(IList<LogEventInfo> logEvents, MemoryStream output)
        {
            var newlineDelimiter = BatchAsJsonArray ? ", " : LineEnding.NewLineCharacters;

            int consumed = 0;

            lock (_reusableEncodingBuilder)
            {
                try
                {
                    var sb = _reusableEncodingBuilder;
                    sb.Length = 0;

                    if (BatchAsJsonArray)
                        sb.Append('[');

                    for (int i = 0; i < logEvents.Count; i++)
                    {
                        if (consumed > 0)
                            sb.Append(newlineDelimiter);

                        Layout.Render(logEvents[i], sb);

                        consumed++;
                        if (sb.Length >= MaxPayloadSizeBytes)
                            break;
                    }

                    if (BatchAsJsonArray)
                        sb.Append(']');

                    EncodePayload(_utf8Encoding, sb, output);
                    return consumed;
                }
                finally
                {
                    if (_reusableEncodingBuilder.Length > _reusableEncodingBuffer.Length)
                        _reusableEncodingBuilder.Remove(0, _reusableEncodingBuilder.Length - 1);    // Attempt soft clear that skips Large-Object-Heap (LOH) re-allocation

                    _reusableEncodingBuilder.Length = 0;
                }
            }
        }

        private HttpContent CreateHttpContent(MemoryStream output, out MemoryStream? compressed)
        {
            compressed = null;
            if (Compress == HttpCompressionType.None)
                return new ByteArrayContent(output.GetBuffer(), 0, (int)output.Length);

            compressed = RentMemoryStream();
            using (var gzip = new GZipStream(compressed,
                Compress == HttpCompressionType.GZipFast ? CompressionLevel.Fastest : CompressionLevel.Optimal,
                leaveOpen: true))
            {
                output.Position = 0;
                output.CopyTo(gzip);
            }

            var content = new ByteArrayContent(compressed.GetBuffer(), 0, (int)compressed.Length);
            content.Headers.ContentEncoding.Add("gzip");
            return content;
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

        private void EncodePayload(Encoding encoder, StringBuilder payload, MemoryStream output)
        {
            output.Position = 0;

            var totalLength = payload.Length;
            lock (_reusableEncodingBuffer)
            {
                if (totalLength < _reusableEncodingBuffer.Length)
                {
                    payload.CopyTo(0, _reusableEncodingBuffer, 0, totalLength);
                    var maxByteCount = ((encoder.GetMaxByteCount(totalLength) / 4096) + 1) * 4096;
                    output.SetLength(maxByteCount);
                    var byteCount = encoder.GetBytes(_reusableEncodingBuffer, 0, totalLength, output.GetBuffer(), 0);
                    output.SetLength(byteCount);
                    output.Position = byteCount;
                }
                else
                {
                    var payloadString = payload.ToString();
                    var maxByteCount = encoder.GetMaxByteCount(payloadString.Length);
                    output.SetLength(maxByteCount);
                    var byteCount = encoder.GetBytes(payloadString, 0, payloadString.Length, output.GetBuffer(), 0);
                    output.SetLength(byteCount);
                    output.Position = byteCount;
                }
            }
        }

        private Uri RenderBaseUrl(LogEventInfo logEventInfo)
        {
            var lastRenderedBaseUri = _lastRenderedBaseUri;

            var baseUrl = RenderLogEvent(Url, logEventInfo);
            if (string.IsNullOrEmpty(baseUrl))
                throw new NLogRuntimeException($"Invalid {nameof(Url)} specified for {GetType()}: {baseUrl}");

            if (lastRenderedBaseUri != null && string.Equals(lastRenderedBaseUri.Item1, baseUrl, StringComparison.Ordinal))
                return lastRenderedBaseUri.Item2;

            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
                throw new NLogRuntimeException($"Invalid {nameof(Url)} specified for {GetType()}: {baseUrl}");

            _lastRenderedBaseUri = new Tuple<string, Uri>(baseUrl, uri);
            return uri;
        }
        private Tuple<string, Uri>? _lastRenderedBaseUri = null;

        private HttpClient ResetHttpClientIfNeeded(Uri? baseUrl)
        {
            var oldHttpClient = _httpClient;

            int nowTickCount = Environment.TickCount;
            if (!HttpClientLifeTimeExpired(nowTickCount, _httpClientLifeTimeTicks) && oldHttpClient != null)
            {
                if (baseUrl is null || oldHttpClient.BaseAddress?.Equals(baseUrl) == true)
                    return oldHttpClient;
            }

            // HttpClient is intended to be long-lived, but DNS changes can cause it to fail. Periodically recycle it to mitigate this.
            lock (_reusableEncodingBuffer)
            {
                oldHttpClient = _httpClient;
                if (!HttpClientLifeTimeExpired(nowTickCount, _httpClientLifeTimeTicks) && oldHttpClient != null && (baseUrl is null || oldHttpClient.BaseAddress?.Equals(baseUrl) == true))
                    return oldHttpClient;

                _httpClient = null;
                oldHttpClient?.Dispose();
                _httpClient = oldHttpClient = CreateNewHttpClient(baseUrl);
                _httpClientCreatedTicks = nowTickCount;
            }

            return oldHttpClient;
        }

        private bool HttpClientLifeTimeExpired(int nowTickCount, int lifetimeTicks)
        {
            var deltaTicks = nowTickCount - _httpClientCreatedTicks;
            return deltaTicks > lifetimeTicks || deltaTicks < -lifetimeTicks;
        }

        private void SignalHttpClientReset()
        {
            if (_httpClientCreatedTicks != 0)
                NLog.Common.InternalLogger.Debug("{0}: Signal HttpClient reset after config change", this);
            lock (_reusableEncodingBuffer)
            {
                _httpClientCreatedTicks = 0;
            }
        }

        private HttpClient CreateNewHttpClient(Uri? baseUrl)
        {
            var nullEvent = LogEventInfo.CreateNullEvent();

            var baseAddress = baseUrl?.ToString() ?? Url?.Render(nullEvent);
            if (_httpClientCreatedTicks == 0)
                NLog.Common.InternalLogger.Info("{0}: Creating HttpClient for BaseAddress: {1}", this, baseAddress);
            else
                NLog.Common.InternalLogger.Debug("{0}: Creating HttpClient for BaseAddress: {1}", this, baseAddress);

            if (baseUrl is null)
            {
                if (!Uri.TryCreate(baseAddress, UriKind.Absolute, out var baseAddressUri))
                    throw new NLogRuntimeException($"Invalid {nameof(Url)} specified for {GetType()}: {baseAddress}");
                baseUrl = baseAddressUri;
            }

            var handler = new HttpClientHandler();

#if !NETFRAMEWORK || NET471_OR_GREATER
            if (SslCertificateFile != null)
            {
                var sslCertificateFile = SslCertificateFile.Render(nullEvent) ?? string.Empty;
                if (!_sslCertificateCache.TryGetCertificate(sslCertificateFile, out var clientCertificates))
                {
                    var sslCertificatePassword = SslCertificatePassword?.Render(nullEvent) ?? string.Empty;
                    try
                    {
                        clientCertificates = _sslCertificateCache.LoadCertificate(sslCertificateFile, sslCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        Common.InternalLogger.Error(ex, "{0}: Failed loading SSL certificate from file: {1}", this, sslCertificateFile);
                        throw new NLogRuntimeException($"{GetType()}: Failed loading SSL certificate from file: {sslCertificateFile}", ex);
                    }
                }

                if (clientCertificates?.Count > 0)
                {
                    handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                    handler.ClientCertificates.AddRange(clientCertificates);
                }
                handler.ServerCertificateCustomValidationCallback = static (message, certificate, chain, sslPolicyErrors) =>
                {
                    if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
                        return true;

                    Common.InternalLogger.Warn("SSL certificate errors were encountered when establishing connection to the server: {0}, Certificate: {1}", sslPolicyErrors, certificate);
                    if (certificate is null)
                        return false;

                    return true;
                };
            }
#endif

            var networkUserName = NetworkUserName?.Render(nullEvent)?.Trim() ?? string.Empty;
            if (NetworkUserName != null)
            {
                handler.PreAuthenticate = true; // Authorization header included upfront (instead of waiting for 401-challenge from server) to avoid extra round-trip and latency
                if (string.IsNullOrWhiteSpace(networkUserName))
                {
                    handler.Credentials = CredentialCache.DefaultCredentials;
                }
                else
                {
                    var networkPassword = NetworkPassword?.Render(nullEvent) ?? string.Empty;
                    handler.Credentials = new NetworkCredential(networkUserName, networkPassword);
                }
            }

            if (ProxyUrl != null)
            {
                var proxyAddress = ProxyUrl?.Render(nullEvent) ?? string.Empty;
                var proxyUser = ProxyUser?.Render(nullEvent) ?? string.Empty;
                var proxyPassword = ProxyPassword?.Render(nullEvent) ?? string.Empty;
                handler.UseProxy = true;
                handler.Proxy = CreateWebProxy(proxyAddress, proxyUser, proxyPassword);
            }
            else
            {
                handler.UseProxy = false;
            }

            var newHttpClient = new HttpClient(handler)
            {
                BaseAddress = baseUrl,
            };
            if (SendTimeoutSeconds > 0)
                newHttpClient.Timeout = TimeSpan.FromSeconds(SendTimeoutSeconds);

            if (KeepAlive)
                newHttpClient.DefaultRequestHeaders.Connection.Add("keep-alive");
            else
                newHttpClient.DefaultRequestHeaders.ConnectionClose = true; // Closes TCP connection after each request (Disables HTTP Keep-Alive)

            if (Expect100Continue.HasValue)
                newHttpClient.DefaultRequestHeaders.ExpectContinue = Expect100Continue.Value;

            foreach (var header in Headers)
            {
                var headerName = header.Name?.Trim();
                if (string.IsNullOrEmpty(headerName))
                    continue;
                var headerValue = header.Layout?.Render(nullEvent) ?? string.Empty;
                if (string.IsNullOrWhiteSpace(headerValue) && !header.IncludeEmptyValue)
                    continue;
                newHttpClient.DefaultRequestHeaders.TryAddWithoutValidation(headerName, headerValue);
            }


            return newHttpClient;
        }

        private IWebProxy? CreateWebProxy(string proxyAddress, string proxyUser, string proxyPassword)
        {
            if (string.IsNullOrEmpty(proxyAddress))
                return WebRequest.DefaultWebProxy;

            if (!Uri.TryCreate(proxyAddress, UriKind.Absolute, out var proxyUri))
                throw new NLogRuntimeException($"Invalid {nameof(ProxyUrl)} specified for {GetType()}: {proxyAddress}");

            var proxy = new WebProxy(proxyUri);
            if (string.IsNullOrEmpty(proxyUser))
            {
                proxy.UseDefaultCredentials = true;
            }
            else
            {
                var cred = proxyUser.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                proxy.Credentials = cred.Length == 1
                    ? new NetworkCredential
                    { UserName = proxyUser, Password = proxyPassword }
                    : new NetworkCredential
                    {
                        Domain = cred[0],
                        UserName = cred[1],
                        Password = proxyPassword
                    };
            }

            return proxy;
        }

        private sealed class LogEventBatch : IList<LogEventInfo>
        {
            private readonly IList<LogEventInfo> _source;
            private readonly int _offset;
            public int Count { get; }
            public bool IsReadOnly => true;

            public LogEventBatch(IList<LogEventInfo> source, int offset, int count)
            {
                _source = source;
                _offset = offset;
                Count = count;
            }

            public LogEventInfo this[int index]
            {
                get => _source[_offset + index];
                set => _source[_offset + index] = value;
            }

            public int IndexOf(LogEventInfo item)
            {
                for (int i = 0; i < Count; i++)
                {
                    if (ReferenceEquals(this[i], item))
                        return i;
                }
                return -1;
            }
            public bool Contains(LogEventInfo item) => IndexOf(item) >= 0;
            public void CopyTo(LogEventInfo[] array, int arrayIndex)
            {
                for (int i = 0; i < Count; i++)
                    array[arrayIndex + i] = this[i];
            }
            public void Add(LogEventInfo item) => throw new NotSupportedException();
            public void Clear() => throw new NotSupportedException();
            public void Insert(int index, LogEventInfo item) => throw new NotSupportedException();
            public bool Remove(LogEventInfo item) => throw new NotSupportedException();
            public void RemoveAt(int index) => throw new NotSupportedException();
            public IEnumerator<LogEventInfo> GetEnumerator()
            {
                for (int i = 0; i < Count; i++)
                    yield return this[i];
            }
            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        }
    }
}
