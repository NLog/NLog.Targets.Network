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

namespace NLog.Targets.Network
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using NLog.Config;
    using NLog.Internal.NetworkSenders;
    using NLog.Targets;
    using Xunit;

    public class HttpNetworkSenderTests
    {
        public HttpNetworkSenderTests()
        {
            LogManager.ThrowExceptions = true;
        }

        /// <summary>
        /// Test <see cref="HttpNetworkSender"/> via <see cref="NetworkTarget"/>
        /// </summary>
        [Fact]
        public void HttpNetworkSenderViaNetworkTargetTest()
        {
            // Arrange
            var networkTarget = new NetworkTarget("target1")
            {
                Address = "http://test.with.mock",
                Layout = "${logger}|${message}|${exception}",
                MaxQueueSize = 1234,
                OnQueueOverflow = NetworkTargetQueueOverflowAction.Block,
                MaxMessageSize = 0,
            };

            var httpMessageHandlerMock = new HttpMessageHandlerMock();
            var networkSenderFactoryMock = new NetworkSenderFactoryMock(httpMessageHandlerMock);
            networkTarget.SenderFactory = networkSenderFactoryMock;

            var logFactory = new LogFactory();
            var config = new LoggingConfiguration(logFactory);
            config.AddRuleForAllLevels(networkTarget);
            logFactory.Configuration = config;

            var logger = logFactory.GetLogger("HttpHappyPathTestLogger");

            // Act
            logger.Info("test message1");
            logFactory.Flush();

            // Assert
            Assert.Equal("http://test.with.mock/", httpMessageHandlerMock.RequestedAddress?.ToString());
            Assert.Equal("HttpHappyPathTestLogger|test message1|", httpMessageHandlerMock.GetRequestContentAsString());
            Assert.Equal(HttpMethod.Post, httpMessageHandlerMock.RequestMethod);
        }

        [Fact]
        public void HttpNetworkSenderViaNetworkTargetRecoveryTest()
        {
            // Arrange
            var networkTarget = new NetworkTarget("target1")
            {
                Address = "http://test.with.mock",
                Layout = "${logger}|${message}|${exception}",
                MaxQueueSize = 1234,
                OnQueueOverflow = NetworkTargetQueueOverflowAction.Block,
                MaxMessageSize = 0,
            };

            var httpMessageHandlerMock = new HttpMessageHandlerMock();
            httpMessageHandlerMock.FirstRequestMustFail = true;
            var networkSenderFactoryMock = new NetworkSenderFactoryMock(httpMessageHandlerMock);
            networkTarget.SenderFactory = networkSenderFactoryMock;

            var logFactory = new LogFactory();
            var config = new LoggingConfiguration(logFactory);
            config.AddRuleForAllLevels(networkTarget);
            logFactory.Configuration = config;

            var logger = logFactory.GetLogger("HttpRecoveryPathTestLogger");

            // Act
            logger.Info("test message1");   // Will fail after short delay
            logger.Info("test message2");   // Will be queued and sent after short delay
            logFactory.Flush();

            // Assert
            Assert.Equal("http://test.with.mock/", httpMessageHandlerMock.RequestedAddress?.ToString());
            Assert.Equal("HttpRecoveryPathTestLogger|test message2|", httpMessageHandlerMock.GetRequestContentAsString());
            Assert.Equal(HttpMethod.Post, httpMessageHandlerMock.RequestMethod);
        }

        private sealed class HttpMessageHandlerMock : HttpMessageHandler
        {
            public Uri RequestedAddress { get; private set; }

            public HttpMethod RequestMethod { get; private set; }

            public bool FirstRequestMustFail { get; set; }

            private byte[] _requestContent = Array.Empty<byte>();

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                RequestedAddress = request.RequestUri;
                RequestMethod = request.Method;

                if (request.Content != null)
                {
                    _requestContent = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                }

                if (FirstRequestMustFail)
                {
                    FirstRequestMustFail = false;
                    _requestContent = Array.Empty<byte>();
                    await Task.Delay(50, cancellationToken).ConfigureAwait(false);
                    throw new InvalidDataException("You are doomed");
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("new response 1")
                };
            }

            public string GetRequestContentAsString()
            {
                return System.Text.Encoding.UTF8.GetString(_requestContent);
            }
        }

        private sealed class NetworkSenderFactoryMock : INetworkSenderFactory
        {
            private readonly HttpMessageHandlerMock _httpMessageHandlerMock;

            public NetworkSenderFactoryMock(HttpMessageHandlerMock httpMessageHandlerMock)
            {
                _httpMessageHandlerMock = httpMessageHandlerMock;
            }

            public QueuedNetworkSender Create(string url, X509Certificate2Collection sslCertificateOverride, NetworkTarget networkTarget)
            {
                return new HttpNetworkSender(url)
                {
                    HttpClientFactory = () => new HttpClient(_httpMessageHandlerMock, disposeHandler: false)
                };
            }
        }
    }
}
