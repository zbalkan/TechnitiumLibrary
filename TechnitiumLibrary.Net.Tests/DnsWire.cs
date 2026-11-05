/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Reflection;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Tests
{
    // Hand-built DNS wire-format datagrams. The owner name of every answer is a
    // compression pointer to the question at offset 12, which keeps the record
    // header a fixed size and lets each test vary only TYPE, RDLENGTH and RDATA.
    internal static class DnsWire
    {
        private static void U16(MemoryStream ms, int v)
        {
            ms.WriteByte((byte)(v >> 8));
            ms.WriteByte((byte)v);
        }

        // Response with one question for "x" IN SRV, then the supplied answer records.
        public static byte[] Response(ushort anCount, params byte[][] answers)
        {
            MemoryStream ms = new MemoryStream();

            U16(ms, 0x1234);    // ID
            U16(ms, 0x8180);    // QR=1, RD=1, RA=1
            U16(ms, 1);         // QDCOUNT
            U16(ms, anCount);   // ANCOUNT
            U16(ms, 0);         // NSCOUNT
            U16(ms, 0);         // ARCOUNT

            // Question: single-label name "x", QTYPE SRV, QCLASS IN.
            ms.WriteByte(1);
            ms.WriteByte((byte)'x');
            ms.WriteByte(0);
            U16(ms, 33);        // SRV
            U16(ms, 1);         // IN

            foreach (byte[] a in answers)
                ms.Write(a, 0, a.Length);

            return ms.ToArray();
        }

        // A resource record whose RDLENGTH is set explicitly, so a test can make it
        // disagree with the real RDATA length. Owner name is a pointer to offset 12.
        public static byte[] Record(int type, int rdlength, byte[] rdata)
        {
            MemoryStream ms = new MemoryStream();

            ms.WriteByte(0xC0);     // compression pointer high byte
            ms.WriteByte(0x0C);     // -> offset 12 (the question name)
            U16(ms, type);          // TYPE
            U16(ms, 1);             // CLASS IN
            ms.WriteByte(0);        // TTL = 120
            ms.WriteByte(0);
            ms.WriteByte(0);
            ms.WriteByte(120);
            U16(ms, rdlength);      // RDLENGTH (caller controls; may lie)

            if (rdata != null)
                ms.Write(rdata, 0, rdata.Length);

            return ms.ToArray();
        }

        // SRV RDATA: priority, weight, port, then a target name. A null label
        // produces a bare root target (used only by well-formed controls).
        public static byte[] SrvRdata(ushort priority, ushort weight, ushort port, string label)
        {
            MemoryStream ms = new MemoryStream();

            U16(ms, priority);
            U16(ms, weight);
            U16(ms, port);

            if (label != null)
            {
                ms.WriteByte((byte)label.Length);
                foreach (char c in label)
                    ms.WriteByte((byte)c);
            }

            ms.WriteByte(0);        // root terminator

            return ms.ToArray();
        }

        public static DnsDatagram Parse(byte[] wire)
        {
            return DnsDatagram.ReadFrom(new MemoryStream(wire));
        }

        // NormalizeName is internal on DnsResourceRecord and runs on every record
        // during cache insertion. Invoke it by reflection so the test stays
        // non-invasive, and surface the real exception rather than the wrapper.
        public static void NormalizeName(DnsResourceRecord record)
        {
            MethodInfo mi = typeof(DnsResourceRecord).GetMethod(
                "NormalizeName", BindingFlags.NonPublic | BindingFlags.Instance);

            if (mi is null)
                throw new InvalidOperationException("DnsResourceRecord.NormalizeName not found; the internal API changed.");

            try
            {
                mi.Invoke(record, null);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            {
                throw ex.InnerException;
            }
        }
    }
}
