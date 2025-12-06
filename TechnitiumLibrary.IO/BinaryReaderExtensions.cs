/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace TechnitiumLibrary.IO
{
    public static class BinaryReaderExtensions
    {
        public static byte[] ReadBuffer(this BinaryReader bR)
        {
            int len = ReadLength(bR);

            byte[] buffer = bR.ReadBytes(len);

            if (buffer.Length != len)
                throw new EndOfStreamException("Unexpected end of stream while reading buffer.");

            return buffer;
        }

        public static string ReadShortString(this BinaryReader bR)
        {
            return ReadShortString(bR, Encoding.UTF8);
        }

        public static string ReadShortString(this BinaryReader bR, Encoding encoding)
        {
            int length = bR.ReadByte();
            byte[] bytes = bR.ReadBytes(length);

            if (bytes.Length != length)
                throw new EndOfStreamException("Not enough bytes to read short string.");

            return encoding.GetString(bytes);
        }

        public static DateTime ReadDateTime(this BinaryReader bR)
        {
            // Read int64 big-endian timestamp (same as original behavior because .NET native is LE)
            Span<byte> buffer = stackalloc byte[8];
            int read = bR.BaseStream.Read(buffer);

            if (read != 8)
                throw new EndOfStreamException("Not enough bytes to read DateTime ticks.");

            long millis = BinaryPrimitives.ReadInt64LittleEndian(buffer);
            return DateTime.UnixEpoch.AddMilliseconds(millis);
        }

        public static int ReadLength(this BinaryReader bR)
        {
            int first = bR.ReadByte();
            if (first < 0)
                throw new EndOfStreamException("Not enough bytes for a length prefix.");

            // Single byte value
            if (first <= 127)
                return first;

            // Otherwise, multi-byte length
            int numberLenBytes = first & 0x7F;

            if (numberLenBytes > 4)
                throw new IOException("BinaryReaderExtension encoding length not supported.");

            Span<byte> temp = stackalloc byte[4];

            int offset = 4 - numberLenBytes;
            int readBytes = bR.BaseStream.Read(temp[offset..]);

            if (readBytes != numberLenBytes)
                throw new EndOfStreamException("Not enough bytes for encoded length.");

            return BinaryPrimitives.ReadInt32BigEndian(temp);
        }
    }
}