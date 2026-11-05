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
    // Regression tests for two defects found while comparing the parser with dnsmasq's
    // CVE-2026-5172. Both are fixed by reconciling bytes consumed against RDLENGTH in
    // DnsResourceRecordData, so a record whose RDATA disagrees with its declared length
    // is rejected into DnsDatagram.ParsingException instead of producing a corrupt record.
    //
    // 1. Empty RDATA (RDLENGTH == 0) on a name-bearing type. The target used to be left
    //    null and faulted later in NormalizeName (the cache path) and UncompressedLength
    //    (the response-sizing path). The record is now rejected at parse time.
    //
    // 2. RDLENGTH that disagrees with a structured type's real length. The length is now
    //    enforced, so an inflated RDLENGTH can no longer shift the parse of the records
    //    that follow.
    [TestClass]
    public class MalformedRdataRejectionTests
    {
        [TestMethod]
        public void EmptyRdataSrv_IsRejected()
        {
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.SRV, 0, null)));

            Assert.IsNotNull(dg.ParsingException, "Empty-RDATA SRV must be rejected, not accepted with a null target.");
            Assert.AreEqual(0, dg.Answer.Count);
        }

        [TestMethod]
        [DataRow(DnsResourceRecordType.SRV)]
        [DataRow(DnsResourceRecordType.MX)]
        [DataRow(DnsResourceRecordType.NS)]
        [DataRow(DnsResourceRecordType.CNAME)]
        [DataRow(DnsResourceRecordType.PTR)]
        public void EmptyRdataNameBearingRecord_IsRejected(DnsResourceRecordType type)
        {
            // Without rejection the parsed record carries a null name that faults on the
            // cache-insertion path, which an attacker-controlled answer can reach for the
            // name being resolved.
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)type, 0, null)));

            Assert.IsNotNull(dg.ParsingException, "Empty-RDATA " + type + " must be rejected.");
            Assert.AreEqual(0, dg.Answer.Count);
        }

        [TestMethod]
        public void InflatedRdlen_IsRejected_AndDoesNotDesyncFollowingRecords()
        {
            // SRV with a real structure of 9 bytes but RDLENGTH claiming 20, followed by a
            // well-formed A record. The over-claimed length is now caught, so the datagram
            // is rejected rather than parsing the following record from the wrong offset.
            byte[] srv = DnsWire.SrvRdata(10, 20, 5060, "a");
            byte[] padded = new byte[20];
            System.Array.Copy(srv, padded, srv.Length);

            byte[] wire = DnsWire.Response(2,
                DnsWire.Record((int)DnsResourceRecordType.SRV, 20, padded),
                DnsWire.Record((int)DnsResourceRecordType.A, 4, new byte[] { 8, 8, 8, 8 }));

            DnsDatagram dg = DnsWire.Parse(wire);

            Assert.IsNotNull(dg.ParsingException, "An RDLENGTH that disagrees with the structure must be rejected.");
        }

        [TestMethod]
        public void WellFormedSrv_UncompressedLength_IsPositive()
        {
            // The sizing path that faulted on a null target must still work for a
            // well-formed record.
            byte[] rdata = DnsWire.SrvRdata(10, 20, 5060, "a");
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.SRV, rdata.Length, rdata)));

            Assert.IsNull(dg.ParsingException);
            DnsSRVRecordData srv = (DnsSRVRecordData)dg.Answer[0].RDATA;
            Assert.IsTrue(srv.UncompressedLength > 0);
        }
    }
}
