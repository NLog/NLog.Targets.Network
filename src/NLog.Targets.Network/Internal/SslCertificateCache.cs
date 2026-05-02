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
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using NLog.Common;

    internal sealed class SslCertificateCache
    {
        private readonly object _cacheLock = new object();
        private volatile Dictionary<string, X509Certificate2Collection>? _cache;

        public bool TryGetCertificate(string sslCertificateFile, out X509Certificate2Collection? clientCertificates)
        {
            var cache = _cache;
            if (cache != null && cache.TryGetValue(sslCertificateFile, out clientCertificates))
                return true;  // Safe to lookup without lock, since immutable collection

            clientCertificates = null;
            return false;
        }

        public X509Certificate2Collection? LoadCertificate(string sslCertificateFile, string sslCertificatePassword)
        {
            if (TryGetCertificate(sslCertificateFile, out var clientCertificates))
                return clientCertificates;

            lock (_cacheLock)
            {
                if (_cache?.TryGetValue(sslCertificateFile, out clientCertificates) == true)
                    return clientCertificates;

                InternalLogger.Debug("Loading SSL certificate from file: {0}", sslCertificateFile);
                clientCertificates = LoadCertificateFromFile(sslCertificateFile, sslCertificatePassword);

                var newCache = new Dictionary<string, X509Certificate2Collection>((_cache?.Count ?? 0) + 1);
                if (_cache != null)
                {
                    foreach (var existingCertificate in _cache)
                        newCache.Add(existingCertificate.Key, existingCertificate.Value);
                }
                newCache[sslCertificateFile] = clientCertificates;
                _cache = newCache;
                return clientCertificates;
            }
        }

        internal static X509Certificate2Collection LoadCertificateFromFile(string sslCertificateFile, string sslCertificatePassword)
        {
            if (string.IsNullOrEmpty(sslCertificateFile))
                return new X509Certificate2Collection();

            if (sslCertificateFile.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
            {
                return LoadCertificateFromPem(sslCertificateFile, sslCertificatePassword);
            }
            else
            {
                return new X509Certificate2Collection(new X509Certificate2(sslCertificateFile, string.IsNullOrEmpty(sslCertificatePassword) ? null : sslCertificatePassword));
            }
        }

        private static X509Certificate2Collection LoadCertificateFromPem(string fileName, string? password = null)
        {
            using (var reader = new System.IO.StreamReader(new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read), Encoding.UTF8))
            {
                var pem = reader.ReadToEnd();
                var allCertificates = TryParseAllPemBlocks(pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
                if (allCertificates.Count == 0)
                    throw new NLogRuntimeException("Invalid PEM format: Missing BEGIN CERTIFICATE header");

                var leafCertificate = new X509Certificate2(allCertificates[0]);

#if NET || NETSTANDARD2_1_OR_GREATER
                try
                {
                    var certWithKey = TryAttachPrivateKeyFromPem(pem, leafCertificate, password);
                    if (certWithKey != null)
                    {
                        leafCertificate.Dispose();
                        leafCertificate = certWithKey;
                    }
                }
                catch
                {
                    leafCertificate.Dispose();
                    throw;
                }
#endif

                var collection = new X509Certificate2Collection();
                collection.Add(leafCertificate);
                for (int i = 1; i < allCertificates.Count; i++)
                {
                    collection.Add(new X509Certificate2(allCertificates[i]));
                }
                return collection;
            }
        }

        private static List<byte[]> TryParseAllPemBlocks(string pem, string header, string footer)
        {
            var results = new List<byte[]>();
            int searchFrom = 0;
            while (true)
            {
                int headerIndex = pem.IndexOf(header, searchFrom, StringComparison.Ordinal);
                if (headerIndex < 0)
                    break;

                int start = headerIndex + header.Length;
                int end = pem.IndexOf(footer, start, StringComparison.Ordinal);
                if (end < 0)
                    throw new NLogRuntimeException($"Invalid PEM format: Missing {footer}");

                string base64 = pem.Substring(start, end - start).Replace("\r", "").Replace("\n", "").Trim();
                if (string.IsNullOrEmpty(base64))
                    throw new NLogRuntimeException($"Invalid PEM format: Missing content between {header} and {footer}");

                results.Add(Convert.FromBase64String(base64));
                searchFrom = end + footer.Length;
            }
            return results;
        }

#if NET || NETSTANDARD2_1_OR_GREATER
        private static byte[]? TryParsePemBlock(string pem, string header, string footer)
        {
            var blocks = TryParseAllPemBlocks(pem, header, footer);
            return blocks.Count > 0 ? blocks[0] : null;
        }

        private static X509Certificate2? TryAttachPrivateKeyFromPem(string pem, X509Certificate2 certificate, string? password)
        {
            byte[]? pkcs8Bytes = TryParsePemBlock(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
            byte[]? rsaPkcs1Bytes = pkcs8Bytes == null ? TryParsePemBlock(pem, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----") : null;
            byte[]? ecPrivKeyBytes = pkcs8Bytes == null ? TryParsePemBlock(pem, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----") : null;
            byte[]? encryptedPkcs8Bytes = (pkcs8Bytes == null && rsaPkcs1Bytes == null && ecPrivKeyBytes == null)
                ? TryParsePemBlock(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----") : null;

            if (pkcs8Bytes == null && rsaPkcs1Bytes == null && ecPrivKeyBytes == null && encryptedPkcs8Bytes == null)
                return null;

            if (encryptedPkcs8Bytes != null && pkcs8Bytes == null && rsaPkcs1Bytes == null && ecPrivKeyBytes == null && string.IsNullOrEmpty(password))
            {
                InternalLogger.Warn("SSL certificate PEM file contains an encrypted private key but no password was provided");
                return null;
            }

            const string rsaOid = "1.2.840.113549.1.1.1";
            const string ecdsaOid = "1.2.840.10045.2.1";
            string keyAlgorithm = certificate.GetKeyAlgorithm();

            if (rsaPkcs1Bytes != null || keyAlgorithm == rsaOid)
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                if (pkcs8Bytes != null)
                    rsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _);
                else if (rsaPkcs1Bytes != null)
                    rsa.ImportRSAPrivateKey(rsaPkcs1Bytes, out _);
                else if (encryptedPkcs8Bytes != null)
                    rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8Bytes, out _);
                else
                    return null;
                return certificate.CopyWithPrivateKey(rsa);
            }
            else if (ecPrivKeyBytes != null || keyAlgorithm == ecdsaOid)
            {
                using var ecdsa = System.Security.Cryptography.ECDsa.Create();
                if (pkcs8Bytes != null)
                    ecdsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _);
                else if (ecPrivKeyBytes != null)
                    ecdsa.ImportECPrivateKey(ecPrivKeyBytes, out _);
                else if (encryptedPkcs8Bytes != null)
                    ecdsa.ImportEncryptedPkcs8PrivateKey(password, encryptedPkcs8Bytes, out _);
                else
                    return null;
                return certificate.CopyWithPrivateKey(ecdsa);
            }

            return null;
        }
#endif
    }
}
