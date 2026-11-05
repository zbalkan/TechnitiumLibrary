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
    // The RDLENGTH reconciliation in DnsResourceRecordData runs for every record type,
    // so its main risk is rejecting well-formed records. These cover the shapes most
    // likely to break under a strict consumed == RDLENGTH check: a compressed name, a
    // multi-name record, a length-driven record, a prebuffered record, and a
    // multi-record message that must stay aligned.
    [TestClass]
    public class WellFormedRecordParsingTests
    {
        [TestMethod]
        public void CompressedExchangeName_Mx_Parses()
        {
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.MX, 4, DnsWire.MxRdataCompressed(10))));

            Assert.IsNull(dg.ParsingException);
            DnsMXRecordData mx = (DnsMXRecordData)dg.Answer[0].RDATA;
            Assert.AreEqual((ushort)10, mx.Preference);
            Assert.AreEqual("x", mx.Exchange);
        }

        [TestMethod]
        public void MultiName_Soa_Parses()
        {
            byte[] rdata = DnsWire.SoaRdata("a", "b", 2026110600, 7200, 1800, 1209600, 3600);
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.SOA, rdata.Length, rdata)));

            Assert.IsNull(dg.ParsingException);
            DnsSOARecordData soa = (DnsSOARecordData)dg.Answer[0].RDATA;
            Assert.AreEqual("a", soa.PrimaryNameServer);
            Assert.AreEqual(2026110600u, soa.Serial);
            Assert.AreEqual(3600u, soa.Minimum);
        }

        [TestMethod]
        public void LengthDriven_Txt_Parses()
        {
            byte[] rdata = DnsWire.TxtRdata("hi");
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.TXT, rdata.Length, rdata)));

            Assert.IsNull(dg.ParsingException);
            DnsTXTRecordData txt = (DnsTXTRecordData)dg.Answer[0].RDATA;
            Assert.AreEqual("hi", txt.GetText());
        }

        [TestMethod]
        public void Prebuffered_Naptr_Parses()
        {
            byte[] rdata = DnsWire.NaptrRdata(1, 2, "s", "e", "", "a");
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(1, DnsWire.Record((int)DnsResourceRecordType.NAPTR, rdata.Length, rdata)));

            Assert.IsNull(dg.ParsingException);
            DnsNAPTRRecordData naptr = (DnsNAPTRRecordData)dg.Answer[0].RDATA;
            Assert.AreEqual((ushort)1, naptr.Order);
            Assert.AreEqual((ushort)2, naptr.Preference);
            Assert.AreEqual("s", naptr.Flags);
            Assert.AreEqual("a", naptr.Replacement);
        }

        [TestMethod]
        public void MultipleWellFormedRecords_StayAligned()
        {
            byte[] srv = DnsWire.SrvRdata(1, 1, 443, "b");
            DnsDatagram dg = DnsWire.Parse(DnsWire.Response(2,
                DnsWire.Record((int)DnsResourceRecordType.SRV, srv.Length, srv),
                DnsWire.Record((int)DnsResourceRecordType.A, 4, new byte[] { 9, 9, 9, 9 })));

            Assert.IsNull(dg.ParsingException);
            Assert.AreEqual(2, dg.Answer.Count);
            Assert.AreEqual(DnsResourceRecordType.SRV, dg.Answer[0].Type);
            Assert.AreEqual(DnsResourceRecordType.A, dg.Answer[1].Type);
        }
    }
}
