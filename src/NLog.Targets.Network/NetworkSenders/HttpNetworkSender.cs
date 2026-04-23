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

namespace NLog.Internal.NetworkSenders
{
    using System;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Http;
    using NLog.Common;

    /// <summary>
    /// Network sender which uses HTTP or HTTPS POST.
    /// </summary>
    internal sealed class HttpNetworkSender : QueuedNetworkSender
    {
        private readonly Uri _addressUri;

        private HttpClient? _httpClient;
        private int _httpClientCreatedTick;

        internal Func<HttpClient>? HttpClientFactory { get; set; }

        internal TimeSpan SendTimeout { get; set; }

        internal X509Certificate2Collection? SslCertificateOverride { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpNetworkSender"/> class.
        /// </summary>
        /// <param name="url">The network URL.</param>
        public HttpNetworkSender(string url)
            : base(url)
        {
            _addressUri = new Uri(Address);
        }

        protected override void BeginRequest(NetworkRequestArgs eventArgs)
        {
            var asyncContinuation = eventArgs.AsyncContinuation;
            var bytes = eventArgs.RequestBuffer;
            var offset = eventArgs.RequestBufferOffset;
            var length = eventArgs.RequestBufferLength;

            var httpClient = GetOrCreateHttpClient();
            var content = new ByteArrayContent(bytes, offset, length);

            httpClient.PostAsync(_addressUri, content).ContinueWith(task =>
            {
                try
                {
                    if (task.IsFaulted)
                    {
                        var ex = task.Exception?.InnerException ?? task.Exception;
                        InternalLogger.Error(ex, "NetworkTarget: Error sending HTTP request to url={0}", _addressUri);
                        CompleteRequest(_ => asyncContinuation(ex));
                    }
                    else if (task.IsCanceled)
                    {
                        throw new OperationCanceledException("HTTP POST request timed out.");
                    }
                    else
                    {
                        task.Result.EnsureSuccessStatusCode();
                        task.Result.Dispose();
                        CompleteRequest(asyncContinuation);
                    }
                }
                catch (Exception ex)
                {
                    InternalLogger.Error(ex, "NetworkTarget: Error sending HTTP request to url={0}", _addressUri);
#if DEBUG
                    if (LogManager.ThrowExceptions)
                    {
                        throw;
                    }
#endif
                    CompleteRequest(_ => asyncContinuation(ex));
                }
            }, System.Threading.CancellationToken.None, System.Threading.Tasks.TaskContinuationOptions.DenyChildAttach, System.Threading.Tasks.TaskScheduler.Default);  // DenyChildAttach - Skip capture SynchronizationContext
        }

        private void CompleteRequest(Common.AsyncContinuation asyncContinuation)
        {
            var nextRequest = base.EndRequest(asyncContinuation, null);    // pendingException = null to keep sender alive
            if (nextRequest.HasValue)
            {
                BeginRequest(nextRequest.Value);
            }
        }

        private HttpClient GetOrCreateHttpClient()
        {
            var httpClient = _httpClient;
            if (httpClient != null)
            {
                var elapsedMilliseconds = Environment.TickCount - _httpClientCreatedTick;
                if (elapsedMilliseconds < 300 * 1000)
                    return httpClient;

                _httpClient = null;
                httpClient.Dispose();
            }

            _httpClientCreatedTick = Environment.TickCount;
            if (HttpClientFactory != null)
            {
                _httpClient = HttpClientFactory();
                return _httpClient;
            }

            var handler = new HttpClientHandler();
            if (SslCertificateOverride != null)
            {
#if !NETFRAMEWORK || NET471_OR_GREATER
                if (SslCertificateOverride.Count > 0)
                    handler.ClientCertificates.AddRange(SslCertificateOverride);
                handler.ServerCertificateCustomValidationCallback = UserCertificateValidationCallback;
#endif
            }

            _httpClient = new HttpClient(handler);
            if (SendTimeout > TimeSpan.Zero)
                _httpClient.Timeout = SendTimeout;

#if NETFRAMEWORK
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;   // Avoid "100-Continue" response which causes extra round-trip and delay
#endif
            return _httpClient;
        }

        protected override void DoClose(Common.AsyncContinuation continuation)
        {
            _httpClient?.Dispose();
            _httpClient = null;
            base.DoClose(continuation);
        }

        private static bool UserCertificateValidationCallback(HttpRequestMessage request, System.Security.Cryptography.X509Certificates.X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Common.InternalLogger.Warn("SSL certificate errors were encountered when establishing connection to the server: {0}, Certificate: {1}", sslPolicyErrors, certificate);
            if (certificate is null)
                return false;

            return true;
        }
    }
}
