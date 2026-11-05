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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Tests
{
    // Regression guards for malformed RDATA. These assert the properties that keep a
    // dnsmasq CVE-2026-5172-style failure (a declared length driving an unchecked read
    // past the record) from turning into a crash here: in managed code a bad length is
    // either a bounds-checked exception or an empty read, and DnsDatagram.ReadFrom
    // catches any parse exception and records it in ParsingException instead of
    // propagating. These tests pass on the current code and should keep passing.
    [TestClass]
    public class MalformedRecordParsingTests
    {
        [TestMethod]
        public void NegativeRdlenArithmetic_IsContained_NotCrash()
        {
            // SSHFP (type 44) reads two bytes then ReadExactly(RDLENGTH - 2). RDLENGTH = 1
            // makes that argument negative, which allocates a negative-length buffer and
            // throws. The guarantee under test is that the throw is contained, not that a
            // particular exception type escapes.
            byte[] rdata = new byte[] { 1, 1, 0, 0, 0, 0 };
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record(44, 1, rdata)));

            Assert.IsNotNull(dg.ParsingException, "A negative RDLENGTH arithmetic result must be surfaced as a parsing exception, never crash the parser.");
        }

        [TestMethod]
        public void OversizedLengthDrivenRdlen_IsContained_NotCrash()
        {
            // TXT (type 16) is length-driven: it reads RDLENGTH bytes. Claiming far more
            // than the datagram holds must end in a contained end-of-stream, not an
            // out-of-bounds read.
            byte[] rdata = new byte[] { 3, (byte)'a', (byte)'b', (byte)'c' };
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record(16, 4096, rdata)));

            Assert.IsNotNull(dg.ParsingException, "An RDLENGTH larger than the available data must be surfaced as a parsing exception.");
        }

        [TestMethod]
        public void WellFormedSrv_Parses_AndNormalizes()
        {
            byte[] rdata = DnsWire.SrvRdata(10, 20, 5060, "a");
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record(33, rdata.Length, rdata)));

            Assert.IsNull(dg.ParsingException);
            Assert.AreEqual(1, dg.Answer.Count);

            DnsResourceRecord record = dg.Answer[0];
            DnsSRVRecordData srv = (DnsSRVRecordData)record.RDATA;
            Assert.AreEqual((ushort)10, srv.Priority);
            Assert.AreEqual("a", srv.Target);

            // The cache-insertion normalisation path works for a well-formed record,
            // which isolates the empty-RDATA case covered by the known-bug tests.
            DnsWire.NormalizeName(record);
        }
    }
}
