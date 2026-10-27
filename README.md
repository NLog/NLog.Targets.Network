# NLog Network Targets
[![CI](https://github.com/NLog/NLog.Targets.Network/actions/workflows/ci.yml/badge.svg)](https://github.com/NLog/NLog.Targets.Network/actions/workflows/ci.yml)

This repository contains three NLog packages for sending log events to network services.

## Packages

### NLog.Targets.Network

[![NLog.Targets.Network](https://badge.fury.io/nu/NLog.Targets.Network.svg)](https://www.nuget.org/packages/NLog.Targets.Network)

TCP and UDP network targets, with optional SSL/TLS support. Also includes layouts and targets for Syslog, Splunk, GELF, and Log4J XML.

[Package README](src/NLog.Targets.Network/README.md) | [Source code](src/NLog.Targets.Network/) | [Network Target documentation](https://github.com/NLog/NLog/wiki/Network-target)

### NLog.Targets.HttpClient

[![NLog.Targets.HttpClient](https://badge.fury.io/nu/NLog.Targets.HttpClient.svg)](https://www.nuget.org/packages/NLog.Targets.HttpClient)

HTTP and HTTPS target with batching, JSON and NDJSON payloads, compression, custom headers, authentication, client certificates, proxy support, and retries.

[Package README](src/NLog.Targets.HttpClient/README.md) | [Source code](src/NLog.Targets.HttpClient/)

### NLog.Targets.OpenTelemetryHttp

[![NLog.Targets.OpenTelemetryHttp](https://badge.fury.io/nu/NLog.Targets.OpenTelemetryHttp.svg)](https://www.nuget.org/packages/NLog.Targets.OpenTelemetryHttp)

OTLP/HTTP exporter that sends logs to an OpenTelemetry Collector, including structured event properties and trace/span correlation.

[Package README](src/NLog.Targets.OpenTelemetryHttp/README.md) | [Source code](src/NLog.Targets.OpenTelemetryHttp/)
