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
            if (string.IsNullOrEmpty(sslCertificateFile))
            {
                clientCertificates = null;
                return true;
            }

            return TryGetCachedCertificate(sslCertificateFile, out clientCertificates);
        }

        public X509Certificate2Collection? LoadCertificate(string sslCertificateFile, string sslCertificatePassword, string sslCertificateThumbprint)
        {
            var cacheKey = ResolveCacheKey(sslCertificateFile, sslCertificateThumbprint);
            if (string.IsNullOrEmpty(cacheKey))
                return null;

            if (TryGetCachedCertificate(cacheKey, out var clientCertificates))
                return clientCertificates;

            lock (_cacheLock)
            {
                if (TryGetCachedCertificate(cacheKey, out clientCertificates))
                    return clientCertificates;

                if (!string.IsNullOrEmpty(sslCertificateFile))
                {
                    sslCertificateFile = System.IO.Path.GetFullPath(sslCertificateFile);
                    InternalLogger.Debug("Loading SSL certificate from file: {0}", sslCertificateFile);
                    clientCertificates = LoadCertificateFromFile(sslCertificateFile, sslCertificatePassword);
                }
                else if (!string.IsNullOrEmpty(sslCertificateThumbprint))
                {
                    sslCertificateThumbprint = NormalizeThumbprint(sslCertificateThumbprint);
                    InternalLogger.Debug("Loading SSL certificate from certificate store with thumbprint: {0}", sslCertificateThumbprint);
                    clientCertificates = LoadCertificateFromStore(StoreLocation.CurrentUser, sslCertificateThumbprint);
                    if (clientCertificates.Count == 0)
                        clientCertificates = LoadCertificateFromStore(StoreLocation.LocalMachine, sslCertificateThumbprint);
                    if (clientCertificates.Count == 0)
                        throw new NLogRuntimeException($"SSL certificate with thumbprint '{sslCertificateThumbprint}' not found in CurrentUser or LocalMachine My store");
                }
                else
                {
                    return new X509Certificate2Collection();
                }

                LogLoadedCertificates(clientCertificates);

                var newCache = new Dictionary<string, X509Certificate2Collection>((_cache?.Count ?? 0) + 1);
                if (_cache != null)
                {
                    foreach (var existingCertificate in _cache)
                        newCache.Add(existingCertificate.Key, existingCertificate.Value);
                }
                newCache[cacheKey] = clientCertificates;
                _cache = newCache;
                return clientCertificates;
            }
        }

        private bool TryGetCachedCertificate(string cacheKey, out X509Certificate2Collection? clientCertificates)
        {
            var cache = _cache;
            if (cache != null && cache.TryGetValue(cacheKey, out clientCertificates))
                return true;  // Safe to lookup without lock, since cache is immutable

            clientCertificates = null;
            return false;
        }

        private static string ResolveCacheKey(string sslCertificateFile, string sslCertificateThumbprint)
        {
            if (!string.IsNullOrEmpty(sslCertificateFile))
                return sslCertificateFile;

            if (!string.IsNullOrEmpty(sslCertificateThumbprint))
                return sslCertificateThumbprint;

            return string.Empty;
        }

        public void Clear()
        {
            _cache = null;
        }

        private static void LogLoadedCertificates(X509Certificate2Collection clientCertificates)
        {
            var utcNow = DateTime.UtcNow;
            var warnUntil = utcNow.AddDays(1);
            for (int i = 0; i < clientCertificates.Count; i++)
            {
                var certificate = clientCertificates[i];
                InternalLogger.Debug("Loaded SSL certificate: Subject={0}, Thumbprint={1}", certificate.Subject, certificate.Thumbprint);

                var notAfterUtc = certificate.NotAfter.ToUniversalTime();
                if (notAfterUtc <= utcNow)
                    InternalLogger.Warn("SSL certificate has expired: Subject={0}, Thumbprint={1}, NotAfter={2}", certificate.Subject, certificate.Thumbprint, certificate.NotAfter);
                else if (notAfterUtc <= warnUntil)
                    InternalLogger.Info("SSL certificate expires soon: Subject={0}, Thumbprint={1}, NotAfter={2}", certificate.Subject, certificate.Thumbprint, certificate.NotAfter);
            }
        }

        private static X509Certificate2Collection LoadCertificateFromFile(string sslCertificateFile, string sslCertificatePassword)
        {
            if (sslCertificateFile.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
            {
                return LoadCertificateFromPem(sslCertificateFile, sslCertificatePassword);
            }
            else
            {
                return new X509Certificate2Collection(new X509Certificate2(sslCertificateFile, string.IsNullOrEmpty(sslCertificatePassword) ? null : sslCertificatePassword));
            }
        }

        private static X509Certificate2Collection LoadCertificateFromStore(StoreLocation storeLocation, string thumbprint)
        {
#if !NET35
            using (var store = new X509Store(StoreName.My, storeLocation))
#else
            var store = new X509Store(StoreName.My, storeLocation);
#endif
            {
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (found.Count == 0)
                    return new X509Certificate2Collection();

                var collection = new X509Certificate2Collection();
                for (int i = 0; i < found.Count; i++)
                    collection.Add(new X509Certificate2(found[i]));
                return collection;
            }
        }

        private static string NormalizeThumbprint(string thumbprint)
        {
            var builder = new StringBuilder(thumbprint.Length);
            for (int i = 0; i < thumbprint.Length; i++)
            {
                char ch = thumbprint[i];
                if (!char.IsWhiteSpace(ch) && ch != ':')
                    builder.Append(char.ToUpperInvariant(ch));
            }
            return builder.ToString();
        }

        private static X509Certificate2Collection LoadCertificateFromPem(string fileName, string? password = null)
        {
            using (var reader = new System.IO.StreamReader(new System.IO.FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read), Encoding.UTF8))
            {
                var pem = reader.ReadToEnd();
                var allCertificates = TryParseAllPemBlocks(pem, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
                if (allCertificates.Count == 0)
                    throw new NLogRuntimeException($"Invalid PEM format: Missing BEGIN CERTIFICATE header in file: {fileName}");

                var leafCertificate = new X509Certificate2(allCertificates[0]);

#if NET || NETSTANDARD2_1_OR_GREATER
                try
                {
                    var certWithKey = TryAttachPrivateKeyFromPem(pem, leafCertificate, password, fileName);
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

                int contentStart = headerIndex + header.Length;
                int footerIndex = pem.IndexOf(footer, contentStart, StringComparison.Ordinal);

                if (footerIndex < 0)
                    throw new NLogRuntimeException($"Invalid PEM format: Missing {footer}");

                string base64 = pem.Substring(contentStart, footerIndex - contentStart);

#if !NET35
                if (string.IsNullOrWhiteSpace(base64))
#else
                if (string.IsNullOrEmpty(base64) || base64.Trim().Length == 0)
#endif
                    throw new NLogRuntimeException($"Invalid PEM format: Missing content between {header} and {footer}");

                try
                {
                    var bytes = Convert.FromBase64String(base64);   // Ignores whitespace by default
                    results.Add(bytes);
                }
                catch (FormatException ex)
                {
                    throw new NLogRuntimeException($"Invalid PEM format: Invalid Base64 content", ex);
                }

                searchFrom = footerIndex + footer.Length;
            }

            return results;
        }

#if NET || NETSTANDARD2_1_OR_GREATER
        private static byte[]? TryParsePemBlock(string pem, string header, string footer)
        {
            var blocks = TryParseAllPemBlocks(pem, header, footer);
            return blocks.Count > 0 ? blocks[0] : null;
        }

        private static X509Certificate2? TryAttachPrivateKeyFromPem(string pem, X509Certificate2 certificate, string? password, string fileName)
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
                InternalLogger.Warn("SSL certificate PEM file contains an encrypted private key but no password was provided in file: {0}", fileName);
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

            InternalLogger.Warn("SSL certificate unable to attach private key. Unsupported key algorithm: {0} in file: {1}", keyAlgorithm, fileName);
            return null;
        }
#endif
    }
}
