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
    /// Sends log messages to HTTP Web-server using either HTTP or HTTPS with support for batching and compression.
    /// </summary>
    /// <remarks>
    /// <a href="https://github.com/nlog/nlog/wiki/HttpClient-target">See NLog Wiki</a>
    /// </remarks>
    /// <seealso href="https://github.com/nlog/nlog/wiki/HttpClient-target">Documentation on NLog Wiki</seealso>
    [Target("HttpClient")]
    public class HttpClientTarget : AsyncTaskTarget
    {
        private static readonly Encoding _utf8Encoding = new UTF8Encoding(false);   // No PreAmble BOM
        private readonly char[] _reusableEncodingBuffer = new char[40 * 1024];  // Avoid large-object-heap
        private readonly StringBuilder _reusableEncodingBuilder = new StringBuilder();
        private volatile HttpClient? _httpClient;
        private TimeSpan _httpClientLifeTime = TimeSpan.FromMinutes(5);
        private DateTime _httpClientCreatedTime = DateTime.MinValue;

        /// <summary>
        /// EndPoint URL for the HTTP Web-server to send to
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
        /// Get or sets the content-type header to use for the http-request. Default is "application/json".
        /// </summary>
        /// <remarks>Default: <see langword="application/json"/></remarks>
        public string ContentType
        {
            get => _contentType;
            set
            {
                if (value == _contentType) return;
                _contentType = string.IsNullOrWhiteSpace(value) ? "application/json" : value;
                _contentTypeHeader = new MediaTypeHeaderValue(_contentType) { CharSet = _utf8Encoding.WebName };
            }
        }
        private string _contentType = "application/json";
        private MediaTypeHeaderValue _contentTypeHeader = new MediaTypeHeaderValue("application/json") { CharSet = _utf8Encoding.WebName };

        /// <summary>
        /// KeepAlive-header to use with the http-request
        /// </summary>
        /// <remarks>Default: <see langword="false"/></remarks>
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
        private bool _keepAlive;

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
        /// Gets or sets a value indicating whether batching LogEvents as a JSON array (Overrides <see cref="LineEnding"/>)
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
        /// Gets or sets the Network credentials to use for HTTP authentication.
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
        /// Gets or sets the Network credentials to use for HTTP authentication.
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
        /// Gets or sets the maximum allowed size, in bytes, before splitting multiple batches when sending log events.
        /// </summary>
        /// <remarks>Default: <see langword="40960"/> bytes. Remember to assign <see cref="AsyncTaskTarget.BatchSize"/> to enable batching.</remarks>
        public int MaxPayloadSizeBytes { get; set; } = 40 * 1024;

        /// <summary>
        /// Type of compression for protocol payload (None / GZip / GZipFast)
        /// </summary>
        /// <remarks>Default: <see langword="None"/></remarks>
        public NetworkTargetCompressionType Compress { get; set; }

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
        /// Gets or sets the layout used for proxy user authentication.
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
        /// Gets or sets the layout used for proxy password authentication.
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
                throw new NLogConfigurationException($"{nameof(Url)} layout must be specified for {nameof(HttpClientTarget)}");

            string baseUrl = Url?.Render(LogEventInfo.CreateNullEvent()) ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(baseUrl))
            {
                if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var _))
                    throw new NLogConfigurationException($"Invalid {nameof(Url)} specified for {nameof(HttpClientTarget)}: {baseUrl}");
            }

            var proxyUrl = ProxyUrl?.Render(LogEventInfo.CreateNullEvent()) ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(proxyUrl))
            {
                if (!Uri.TryCreate(proxyUrl, UriKind.Absolute, out var _))
                    throw new NLogConfigurationException($"Invalid {nameof(ProxyUrl)} specified for {nameof(HttpClientTarget)}: {proxyUrl}");
            }

            base.InitializeTarget();
        }

        /// <inheritdoc />
        protected override void CloseTarget()
        {
            var oldHttpClient = _httpClient;
            _httpClient = null;
            _httpClientCreatedTime = DateTime.MinValue;
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
            if (logEvents.Count == 0)
                return;

            int lastBatchSize = 0;
            var httpContent = Compress == NetworkTargetCompressionType.None ? BuildChunk(logEvents, 0, out lastBatchSize) : CompressChunk(logEvents, 0, out lastBatchSize);
            {
                using var _ = await HttpClientSendAsync(null, httpContent, cancellationToken).ConfigureAwait(false);
            }
            if (lastBatchSize != logEvents.Count)
            {
                await HttpSendBatchesAsync(lastBatchSize, logEvents, cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task HttpSendBatchesAsync(int lastBatchSize, IList<LogEventInfo> logEvents, CancellationToken cancellationToken)
        {
            int batchStartIndex = lastBatchSize;
            while (batchStartIndex < logEvents.Count)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var httpContent = Compress == NetworkTargetCompressionType.None ? BuildChunk(logEvents, batchStartIndex, out lastBatchSize) : CompressChunk(logEvents, batchStartIndex, out lastBatchSize);
                using var _ = await HttpClientSendAsync(null, httpContent, cancellationToken).ConfigureAwait(false);
                batchStartIndex += lastBatchSize;
            }
        }

        /// <summary>
        /// Send an HTTP request as an asynchronous operation.
        /// </summary>
        /// <remarks>Support custom <see cref="HttpClientTarget"/> overrides of WriteAsyncTask, that calls with custom ByteArrayContent / StreamContent</remarks>
        /// <param name="baseAddress">Override the <see cref="HttpClient.BaseAddress"/></param>
        /// <param name="httpContent">The contents of the HTTP message</param>
        /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
        /// <returns>HTTP response with status-code and data (Remember to Dispose the response)</returns>
        protected async Task<HttpResponseMessage> HttpClientSendAsync(Uri? baseAddress, HttpContent httpContent, CancellationToken cancellationToken)
        {
            var httpClient = ResetHttpClientIfNeeded(baseAddress);

            HttpStatusCode httpStatusCode = default(HttpStatusCode);

            try
            {
                using var httpRequest = new HttpRequestMessage(_httpMethod, string.Empty) { Content = httpContent };
                httpRequest.Content.Headers.ContentType = _contentTypeHeader;
                var httpResponseMessage = await httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
                httpStatusCode = httpResponseMessage.StatusCode;
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

                    // Swallow other failures (e.g. 400 Bad Request) without retrying
                    NLog.Common.InternalLogger.Error(ex, "{0}: HTTP request failed with status code {1}", this, (int)httpStatusCode);
                }
                return httpResponseMessage;
            }
            catch (Exception ex)
            {
                NLog.Common.InternalLogger.Error(ex, "{0}: HTTP request failed", this);
                throw;
            }
        }

        private HttpContent BuildChunk(IList<LogEventInfo> logEvents, int startIndex, out int batchSize)
        {
            var newLineCharacters = LineEnding.NewLineCharacters;
            var endIndex = logEvents.Count;

            batchSize = 1;

            lock (_reusableEncodingBuilder)
            {
                try
                {
                    var sb = _reusableEncodingBuilder;
                    sb.Length = 0;

                    if (BatchAsJsonArray)
                        sb.Append('[');

                    Layout.Render(logEvents[startIndex], sb);
                    if (sb.Length < MaxPayloadSizeBytes)
                    {
                        batchSize = endIndex - startIndex;
                        for (int i = startIndex + 1; i < endIndex; ++i)
                        {
                            var orgLength = sb.Length;
                            sb.Append(BatchAsJsonArray ? ", " : newLineCharacters);
                            Layout.Render(logEvents[i], sb);
                            if (sb.Length >= MaxPayloadSizeBytes)
                            {
                                sb.Length = orgLength;   // Remove last rendered log that caused overflow
                                batchSize = i - startIndex;
                                break;
                            }
                        }
                    }

                    if (BatchAsJsonArray)
                        sb.Append(']');

                    return new ByteArrayContent(EncodePayload(_utf8Encoding, sb));
                }
                finally
                {
                    if (_reusableEncodingBuilder.Length > _reusableEncodingBuffer.Length)
                        _reusableEncodingBuilder.Remove(0, _reusableEncodingBuilder.Length - 1);  // Attempt soft clear that skips Large-Object-Heap (LOH) re-allocation
                    _reusableEncodingBuilder.Length = 0;
                }
            }
        }

        private HttpContent CompressChunk(IList<LogEventInfo> logEvents, int startIndex, out int batchSize)
        {
            var endIndex = logEvents.Count;
            batchSize = endIndex - startIndex;

            var output = new MemoryStream();
            var compressionLevel = Compress == NetworkTargetCompressionType.GZipFast ? CompressionLevel.Fastest : CompressionLevel.Optimal;
            var newLineCharacters = LineEnding.NewLineCharacters;

            using (var gzipStream = new GZipStream(output, compressionLevel, true))
            {
                using (var streamWriter = new StreamWriter(gzipStream, _utf8Encoding, 1024, true))
                {
                    if (BatchAsJsonArray)
                        streamWriter.Write('[');

                    for (int i = startIndex; i < endIndex; ++i)
                    {
                        if (i > startIndex)
                        {
                            if (output.Position >= MaxPayloadSizeBytes)
                            {
                                batchSize = i - startIndex;
                                break;
                            }
                            streamWriter.Write(BatchAsJsonArray ? ", " : newLineCharacters);
                        }
                        RenderLogEventForChunk(logEvents[i], streamWriter);
                    }

                    if (BatchAsJsonArray)
                        streamWriter.Write(']');
                }
            }

            output.Position = 0;

            var content = new StreamContent(output);
            content.Headers.Add("Content-Encoding", "gzip");
            return content;
        }

        private void RenderLogEventForChunk(LogEventInfo logEvent, StreamWriter streamWriter)
        {
            lock (_reusableEncodingBuilder)
            {
                try
                {
                    var sb = _reusableEncodingBuilder;
                    sb.Length = 0;

                    Layout.Render(logEvent, sb);

                    if (sb.Length < _reusableEncodingBuffer.Length)
                    {
                        lock (_reusableEncodingBuffer)
                        {
                            sb.CopyTo(0, _reusableEncodingBuffer, 0, sb.Length);
                            streamWriter.Write(_reusableEncodingBuffer, 0, sb.Length);
                        }
                    }
                    else
                    {
                        streamWriter.Write(sb.ToString());
                    }
                }
                finally
                {
                    if (_reusableEncodingBuilder.Length > _reusableEncodingBuffer.Length)
                        _reusableEncodingBuilder.Remove(0, _reusableEncodingBuilder.Length - 1);  // Attempt soft clear that skips Large-Object-Heap (LOH) re-allocation
                    _reusableEncodingBuilder.Length = 0;
                }
            }
        }

        byte[] EncodePayload(Encoding encoder, StringBuilder payload)
        {
            var totalLength = payload.Length;
            lock (_reusableEncodingBuffer)
            {
                if (totalLength < _reusableEncodingBuffer.Length)
                {
                    payload.CopyTo(0, _reusableEncodingBuffer, 0, totalLength);
                    return encoder.GetBytes(_reusableEncodingBuffer, 0, totalLength);
                }

                return encoder.GetBytes(payload.ToString());
            }
        }

        private HttpClient ResetHttpClientIfNeeded(Uri? url)
        {
            var oldHttpClient = _httpClient;

            DateTime utcNow = DateTime.UtcNow;
            if (utcNow - _httpClientCreatedTime < _httpClientLifeTime && oldHttpClient != null)
            {
                if (url is null || oldHttpClient.BaseAddress.Equals(url))
                    return oldHttpClient;
            }

            // HttpClient is intended to be long-lived, but DNS changes can cause it to fail. Periodically recycle it to mitigate this.
            lock (_reusableEncodingBuffer)
            {
                oldHttpClient = _httpClient;
                if (utcNow - _httpClientCreatedTime < _httpClientLifeTime && oldHttpClient != null)
                    return oldHttpClient;

                _httpClient = null;
                oldHttpClient?.Dispose();
                _httpClient = oldHttpClient = CreateNewHttpClient(url);
                _httpClientCreatedTime = DateTime.UtcNow;
            }

            return oldHttpClient;
        }

        private void SignalHttpClientReset()
        {
            if (_httpClientCreatedTime != DateTime.MinValue)
                NLog.Common.InternalLogger.Debug("{0}: Signal HttpClient reset after config change", this);
            lock (_reusableEncodingBuffer)
            {
                _httpClientCreatedTime = DateTime.MinValue;
            }
        }

        private HttpClient CreateNewHttpClient(Uri? url)
        {
            var nullEvent = LogEventInfo.CreateNullEvent();

            var baseAddress = url?.ToString() ?? Url?.Render(nullEvent);
            if (_httpClientCreatedTime == DateTime.MinValue)
                NLog.Common.InternalLogger.Info("{0}: Creating HttpClient for BaseAddress: {1}", this, baseAddress);
            else
                NLog.Common.InternalLogger.Debug("{0}: Creating HttpClient for BaseAddress: {1}", this, baseAddress);
            if (!Uri.TryCreate(baseAddress, UriKind.Absolute, out var baseAddressUri))
                throw new NLogRuntimeException($"Invalid {nameof(Url)} specified for {nameof(HttpClientTarget)}: {baseAddress}");

            
            var handler = new HttpClientHandler();

#if !NETFRAMEWORK || NET471_OR_GREATER
            if (SslCertificateFile != null)
            {
                var sslCertificateFile = SslCertificateFile.Render(nullEvent) ?? string.Empty;
                try
                {
                    var sslCertificatePassword = SslCertificatePassword?.Render(nullEvent) ?? string.Empty;
                    var clientCertificates = NetworkTarget.LoadSslCertificateFromFile(sslCertificateFile, sslCertificatePassword);
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
                catch (Exception ex)
                {
                    Common.InternalLogger.Error(ex, "{0}: Failed loading SSL certificate from file: {1}", this, sslCertificateFile);
                    throw new NLogRuntimeException($"NetworkTarget: Failed loading SSL certificate from file: {sslCertificateFile}", ex);
                }
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
                BaseAddress = baseAddressUri,
            };
            if (SendTimeoutSeconds > 0)
                newHttpClient.Timeout = TimeSpan.FromSeconds(SendTimeoutSeconds);

            if (!KeepAlive)
            {
                newHttpClient.DefaultRequestHeaders.ConnectionClose = true;
            }
            else
            {
                newHttpClient.DefaultRequestHeaders.Add("Keep-Alive", "timeout=5, max=1000");
            }

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

        private static IWebProxy CreateWebProxy(string proxyAddress, string proxyUser, string proxyPassword)
        {
            if (string.IsNullOrEmpty(proxyAddress))
                return WebRequest.DefaultWebProxy;

            if (!Uri.TryCreate(proxyAddress, UriKind.Absolute, out var proxyUri))
                throw new NLogRuntimeException($"Invalid {nameof(ProxyUrl)} specified for {nameof(HttpClientTarget)}: {proxyAddress}");

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
    }
}

#endif
