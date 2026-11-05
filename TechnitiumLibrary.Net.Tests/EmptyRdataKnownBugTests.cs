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
    // Reproductions of two defects found while comparing the parser with dnsmasq's
    // CVE-2026-5172. They assert the corrected behaviour and therefore FAIL on the
    // current code; the TestCategory keeps them out of the CI gate until a fix lands.
    //
    // 1. Empty RDATA (RDLENGTH == 0). DnsResourceRecordData skips ReadRecordData when
    //    RDLENGTH is zero, so a name-bearing record is accepted with a null target.
    //    The null surfaces as a NullReferenceException in NormalizeName (the cache
    //    path) and in UncompressedLength (the response-sizing path).
    //
    // 2. Inflated RDLENGTH on a structured type. SRV and the other name-bearing types
    //    are parsed by structure and ignore RDLENGTH, and nothing reconciles the stream
    //    position with RDLENGTH afterwards. An RDLENGTH larger than the real structure
    //    shifts the parse of every following record with no error raised.
    [TestClass]
    public class EmptyRdataKnownBugTests
    {
        [TestMethod]
        [TestCategory("KnownBug")]
        public void EmptyRdataSrv_ParsesWithNonNullTarget()
        {
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record(33, 0, null)));

            Assert.IsNull(dg.ParsingException, "Empty-RDATA SRV is accepted by the parser.");

            DnsSRVRecordData srv = (DnsSRVRecordData)dg.Answer[0].RDATA;
            Assert.IsNotNull(srv.Target, "A parsed SRV record must not carry a null target.");
        }

        [TestMethod]
        [TestCategory("KnownBug")]
        [DataRow(DnsResourceRecordType.SRV)]
        [DataRow(DnsResourceRecordType.MX)]
        [DataRow(DnsResourceRecordType.NS)]
        [DataRow(DnsResourceRecordType.CNAME)]
        [DataRow(DnsResourceRecordType.PTR)]
        public void EmptyRdataNameBearingRecord_NormalizeName_DoesNotThrow(DnsResourceRecordType type)
        {
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)type, 0, null)));
            Assert.IsNull(dg.ParsingException);

            // Current behaviour: NullReferenceException. The cache insertion path calls
            // this on every record, so an attacker-controlled empty RDATA faults the
            // resolution of the name being looked up.
            DnsWire.NormalizeName(dg.Answer[0]);
        }

        [TestMethod]
        [TestCategory("KnownBug")]
        public void EmptyRdataSrv_UncompressedLength_DoesNotThrow()
        {
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record(33, 0, null)));
            DnsSRVRecordData srv = (DnsSRVRecordData)dg.Answer[0].RDATA;

            // Current behaviour: NullReferenceException via GetSerializeDomainNameLength(null).
            int length = srv.UncompressedLength;
            Assert.IsTrue(length >= 0);
        }

        [TestMethod]
        [TestCategory("KnownBug")]
        public void StructuredRecord_InflatedRdlen_DoesNotDesyncFollowingRecords()
        {
            // SRV with real structure of 9 bytes but RDLENGTH claiming 20, followed by a
            // well-formed A record. If RDLENGTH were honoured the A record would parse as
            // type A. Current behaviour reads the SRV by structure, leaving 11 claimed
            // bytes unconsumed, so the following record is parsed from the wrong offset
            // and mis-typed, with no parsing exception raised.
            byte[] srv = DnsWire.SrvRdata(10, 20, 5060, "a");
            byte[] padded = new byte[20];
            System.Array.Copy(srv, padded, srv.Length);

            byte[] wire = DnsWire.Response(2,
                DnsWire.Record(33, 20, padded),
                DnsWire.Record(1, 4, new byte[] { 8, 8, 8, 8 }));

            DnsDatagram dg = DnsWire.Parse(wire);

            Assert.IsNull(dg.ParsingException);
            Assert.AreEqual(2, dg.Answer.Count);
            Assert.AreEqual(DnsResourceRecordType.SRV, dg.Answer[0].Type);
            Assert.AreEqual(DnsResourceRecordType.A, dg.Answer[1].Type,
                "An inflated RDLENGTH on the SRV must not shift parsing of the following record.");
        }
    }
}
