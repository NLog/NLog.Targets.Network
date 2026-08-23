using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NLog.Internal;

namespace NLog.Targets.OpenTelemetryHttp.Tests
{
    internal static class ProtobufParser
    {
        internal struct ProtobufField
        {
            public int FieldNumber;
            public int WireType;
            public byte[] Data;

            public override string ToString()
            {
                string value;

                try
                {
                    switch (WireType)
                    {
                        case OtlpProtobufSerializer.WireType.Varint: value = AsInt64().ToString(); break;
                        case OtlpProtobufSerializer.WireType.Fixed64: value = Data.Length == 8 ? AsUInt64().ToString() : null; break;
                        case OtlpProtobufSerializer.WireType.LengthDelimited: value = AsMessage().Count > 0 ? $"{AsMessage().Count} Fields" : AsString(); break;
                        case OtlpProtobufSerializer.WireType.Fixed32: value = BitConverter.ToUInt32(Data, 0).ToString(); break;
                        default: value = $"{Data.Length} bytes"; break;
                    };
                }
                catch
                {
                    value = WireType == OtlpProtobufSerializer.WireType.LengthDelimited ? AsString() : $"{Data.Length} bytes";
                }

                return $"Field {FieldNumber} (WireType={WireType}, Value={value})";
            }

            public string AsString()
            {
                EnsureWireType(OtlpProtobufSerializer.WireType.LengthDelimited);
                return Encoding.UTF8.GetString(Data);
            }

            public List<ProtobufField> AsMessage()
            {
                EnsureWireType(OtlpProtobufSerializer.WireType.LengthDelimited);
                return ReadProtobufFields(Data);
            }

            public ProtobufField AsAnyValue()
            {
                var fields = AsMessage();
                if (fields.Count != 1)
                    throw new InvalidOperationException($"AnyValue expected exactly 1 field, got {fields.Count} for Field {FieldNumber}");

                var value = fields[0];
                // 1 = string, 2 = bool, 3 = int, 4 = double, 5 = array, 6 = kvlist
                if (value.FieldNumber < OtlpProtobufSerializer.AnyValueField.StringValue || value.FieldNumber > OtlpProtobufSerializer.AnyValueField.KvListValue)
                    throw new InvalidOperationException($"Invalid AnyValue field {value.FieldNumber} in Field {FieldNumber}");
                return value;
            }

            public string AsAnyValueString()
            {
                var value = AsAnyValue();
                if (value.FieldNumber != OtlpProtobufSerializer.AnyValueField.StringValue)
                    throw new InvalidOperationException($"Expected AnyValue.string_value (field {OtlpProtobufSerializer.AnyValueField.StringValue}), but found field {value.FieldNumber}");
                return value.AsString();
            }

            public long AsInt64()
            {
                EnsureWireType(OtlpProtobufSerializer.WireType.Varint);
                int offset = 0;
                return (long)ReadVarint(Data, ref offset);
            }

            public ulong AsUInt64()
            {
                EnsureWireType(OtlpProtobufSerializer.WireType.Fixed64);
                EnsureDataLength(8);
                return BitConverter.ToUInt64(Data, 0);
            }

            public double AsDouble()
            {
                EnsureWireType(OtlpProtobufSerializer.WireType.Fixed64);
                EnsureDataLength(8);
                return BitConverter.ToDouble(Data, 0);
            }

            public ProtobufField GetField(int fieldNumber) => ProtobufExtensions.GetField(AsMessage(), fieldNumber);
            public List<ProtobufField> AsArrayValue() => GetField(OtlpProtobufSerializer.AnyValueField.ArrayValue).AsMessage();

            private void EnsureWireType(int expected)
            {
                if (WireType != expected)
                    throw new InvalidOperationException(
                        $"Expected wire type {expected}, got {WireType} for Field {FieldNumber}");
            }

            private void EnsureDataLength(int expected)
            {
                if (Data.Length != expected)
                    throw new InvalidOperationException(
                        $"Expected data length {expected}, got {Data.Length} for Field {FieldNumber}");
            }
        }

        public static ProtobufField GetScopeLogs(byte[] data)
        {
            var resourceLogs = ReadProtobufFields(data).GetField(1);
            var scopeLogs = resourceLogs.GetField(2);
            if (scopeLogs.WireType != 2)
                throw new InvalidOperationException($"ScopeLogs must be length-delimited (wire type 2), got {scopeLogs.WireType}");
            return scopeLogs;
        }

        public static ProtobufField GetLogRecord(byte[] data)
        {
            var logRecord = GetLogRecords(data).GetField(2);
            if (logRecord.WireType != 2)
                throw new InvalidOperationException($"LogRecord must be length-delimited (wire type 2), got {logRecord.WireType}");
            return logRecord;
        }

        public static List<ProtobufField> GetLogRecords(byte[] data)
        {
            var logRecords = GetScopeLogs(data).AsMessage().Where(f => f.FieldNumber == 2).ToList();
            foreach (var logRecord in logRecords)
            {
                if (logRecord.WireType != 2)
                    throw new InvalidOperationException($"LogRecord must be length-delimited (wire type 2), got {logRecord.WireType}");
            }
            return logRecords;
        }

        internal static Dictionary<string, ProtobufField> GetLogRecordAttributes(byte[] data)
        {
            var logRecord = GetLogRecord(data).AsMessage();
            return logRecord.GetFieldValues(6);
        }

        internal static Dictionary<string, ProtobufField> GetResourceAttributes(byte[] data)
        {
            var resourceLogs = ReadProtobufFields(data).GetField(1);
            var resource = resourceLogs.GetField(1).AsMessage();
            return resource.GetFieldValues(1);  // Resource.attributes
        }

        private static List<ProtobufField> ReadProtobufFields(byte[] data)
        {
            var fields = new List<ProtobufField>();
            int offset = 0;
            while (offset < data.Length)
            {
                ulong tag = ReadVarint(data, ref offset);
                int fieldNumber = (int)(tag >> 3);
                int wireType = (int)(tag & 0x7);

                byte[] fieldData;
                switch (wireType)
                {
                    case OtlpProtobufSerializer.WireType.Varint:
                        var start = offset;
                        ReadVarint(data, ref offset);
                        fieldData = new byte[offset - start];
                        Array.Copy(data, start, fieldData, 0, fieldData.Length);
                        break;
                    case OtlpProtobufSerializer.WireType.Fixed64:
                        fieldData = new byte[8];
                        Array.Copy(data, offset, fieldData, 0, 8);
                        offset += 8;
                        break;
                    case OtlpProtobufSerializer.WireType.LengthDelimited:
                        var length = (int)ReadVarint(data, ref offset);
                        fieldData = new byte[length];
                        Array.Copy(data, offset, fieldData, 0, length);
                        offset += length;
                        break;
                    case OtlpProtobufSerializer.WireType.Fixed32:
                        fieldData = new byte[4];
                        Array.Copy(data, offset, fieldData, 0, 4);
                        offset += 4;
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown protobuf wire type {wireType} at offset {offset}");
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
                byte b = data[offset++];
                value |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                    break;
                shift += 7;
            }
            return value;
        }
    }

    internal static class ProtobufExtensions
    {
        internal static ProtobufParser.ProtobufField GetField(this List<ProtobufParser.ProtobufField> fields, int fieldNumber)
        {
            ProtobufParser.ProtobufField? match = null;
            foreach (var field in fields)
            {
                if (field.FieldNumber == fieldNumber)
                {
                    if (match != null)
                        throw new InvalidOperationException($"Multiple fields with number {fieldNumber} found");
                    match = field;
                }
            }
            if (match == null)
                throw new InvalidOperationException($"Field with number {fieldNumber} not found");
            return match.Value;
        }

        public static Dictionary<string, ProtobufParser.ProtobufField> GetFieldValues(this List<ProtobufParser.ProtobufField> fields, int fieldNumber)
        {
            var result = new Dictionary<string, ProtobufParser.ProtobufField>();
            foreach (var field in fields)
            {
                if (field.FieldNumber != fieldNumber)
                    continue;

                if (field.WireType != OtlpProtobufSerializer.WireType.LengthDelimited)
                    throw new InvalidOperationException(
                        $"Expected KeyValue to be length-delimited (wire type {OtlpProtobufSerializer.WireType.LengthDelimited}), got {field.WireType}");

                var kvFields = field.AsMessage();
                var key = kvFields.GetField(1).AsString();
                if (string.IsNullOrWhiteSpace(key))
                    throw new InvalidOperationException("Key is empty");

                var valueField = kvFields.Find(f => f.FieldNumber == 2);
                result.Add(key, valueField);
            }
            return result;
        }
    }
}
