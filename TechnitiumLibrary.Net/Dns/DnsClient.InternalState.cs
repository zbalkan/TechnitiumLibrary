/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public partial class DnsClient
    {
        private class InternalState
        {
            public bool DnssecValidationState;
            public int HopCount;
            public IReadOnlyList<DnsResourceRecord>? LastDSRecords;
            public Exception? LastException;
            public DnsDatagram? LastResponse;
            public int NameServerIndex;
            public IList<NameServerAddress> NameServers;
            public DnsQuestionRecord Question;
            public string? ZoneCut;
            public InternalState()
            {
            }

            public InternalState(DnsQuestionRecord question, string zoneCut, bool dnssecValidationState, IReadOnlyList<DnsResourceRecord> lastDSRecords, IList<NameServerAddress> nameServers, int nameServerIndex, int hopCount, DnsDatagram lastResponse, Exception lastException)
            {
                Question = question;
                ZoneCut = zoneCut;
                DnssecValidationState = dnssecValidationState;
                LastDSRecords = lastDSRecords;
                NameServers = nameServers;
                NameServerIndex = nameServerIndex;
                HopCount = hopCount;
                LastResponse = lastResponse;
                LastException = lastException;
            }

            public InternalState DeepClone()
            {
                var serializer = new DataContractSerializer(typeof(InternalState));
                using var ms = new MemoryStream();
                serializer.WriteObject(ms, this);
                ms.Position = 0;
                return (InternalState)serializer.ReadObject(ms)!;
            }
        }
    }
}