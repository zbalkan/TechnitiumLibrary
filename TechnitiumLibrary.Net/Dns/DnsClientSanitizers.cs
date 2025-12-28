using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
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

namespace TechnitiumLibrary.Net.Dns
{
    internal static class DnsClientSanitizers
    {
        public static DnsDatagram SanitizeResponseAfterDnssecValidation(DnsDatagram response)
        {
            List<DnsResourceRecord> newAnswer = null;
            List<DnsResourceRecord> newAuthority = null;

            foreach (DnsResourceRecord record in response.Answer)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                //remove indeterminate records from answer
                newAnswer = new List<DnsResourceRecord>(response.Answer.Count);

                foreach (DnsResourceRecord record2 in response.Answer)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                        continue;

                    newAnswer.Add(record2);
                }

                break;
            }

            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                if (record.Type == DnsResourceRecordType.NS)
                    continue;

                //remove indeterminate records from authority except for NS
                newAuthority = new List<DnsResourceRecord>(response.Authority.Count);

                foreach (DnsResourceRecord record2 in response.Authority)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                    {
                        if (record2.Type != DnsResourceRecordType.NS)
                            continue;
                    }

                    newAuthority.Add(record2);
                }

                break;
            }

            if ((newAnswer is null) && (newAuthority is null))
                return response;

            return response.Clone(newAnswer, newAuthority);
        }


        public static DnsDatagram SanitizeResponseAdditionalForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
            {
                //zone cut is root, do nothing
                return response;
            }

            //remove records from additional section that are not in the zone cut

            if (response.Additional.Count > 0)
            {
                bool additionalNotInZoneCut = false;
                string zoneCutEnd = "." + zoneCut;

                foreach (DnsResourceRecord additional in response.Additional)
                {
                    if (additional.Type == DnsResourceRecordType.OPT)
                        continue;

                    if (!additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    {
                        additionalNotInZoneCut = true;
                        break;
                    }
                }

                if (additionalNotInZoneCut)
                {
                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord additional in response.Additional)
                    {
                        if (additional.Type == DnsResourceRecordType.OPT)
                        {
                            newAdditional.Add(additional);
                            continue;
                        }

                        if (!additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                            continue;

                        newAdditional.Add(additional);
                    }

                    return response.Clone(null, null, newAdditional);
                }
            }

            return response;
        }

        public static DnsDatagram SanitizeResponseAnswerForQName(DnsDatagram response)
        {
            bool fixAnswer = false;

            foreach (DnsQuestionRecord question in response.Question)
            {
                switch (question.Type)
                {
                    case DnsResourceRecordType.AXFR:
                    case DnsResourceRecordType.IXFR:
                        continue;
                }

                string qName = question.Name;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (qName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                qName = (answer.RDATA as DnsCNAMERecordData).Domain;
                                continue;

                            case DnsResourceRecordType.RRSIG:
                                continue;

                            default:
                                if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                    continue;

                                break;
                        }
                    }
                    else
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.RRSIG:
                                continue;

                            case DnsResourceRecordType.DNAME:
                                if (qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                    continue; //found DNAME, continue next

                                break;
                        }
                    }

                    fixAnswer = true;
                    break;
                }

                if (fixAnswer)
                    break;
            }

            if (!fixAnswer)
                return response;

            //fix answer
            List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(response.Answer.Count);

            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                do
                {
                    string nextQName = null;

                    foreach (DnsResourceRecord answer in response.Answer)
                    {
                        if (qName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (answer.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    newAnswers.Add(answer);

                                    nextQName = (answer.RDATA as DnsCNAMERecordData).Domain;
                                    break;

                                case DnsResourceRecordType.RRSIG:
                                    newAnswers.Add(answer);
                                    break;

                                default:
                                    if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                        newAnswers.Add(answer);

                                    break;
                            }
                        }
                        else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            //found DNAME
                            newAnswers.Add(answer);
                        }
                    }

                    qName = nextQName;
                }
                while (qName is not null);
            }

            return response.Clone(newAnswers);
        }

        public static DnsDatagram SanitizeResponseAnswerForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (response.Question.Count < 1)
                return response;

            string qName = response.Question[0].Name;
            string zoneCutEnd = zoneCut.Length > 0 ? "." + zoneCut : zoneCut;

            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord answer = response.Answer[i];

                if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                    continue; //found DNAME, continue next

                if (answer.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                {
                    if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                if (i < response.Answer.Count - 1)
                                    qName = (answer.RDATA as DnsCNAMERecordData).Domain;

                                break;
                        }

                        continue;
                    }

                    switch (answer.Type)
                    {
                        case DnsResourceRecordType.RRSIG:
                            continue;

                        case DnsResourceRecordType.DNAME:
                            if (qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                continue; //found DNAME, continue next

                            break;
                    }
                }

                //name mismatch or not in zone cut
                //truncate answer upto previous RR

                List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(i);

                for (int j = 0; j < i; j++)
                    newAnswers.Add(response.Answer[j]);

                return response.Clone(newAnswers);
            }

            return response;
        }

        public static DnsDatagram SanitizeResponseAuthorityForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
            {
                //zone cut is root, do nothing
                return response;
            }

            //remove SOA/NS records from authority section that are not in the zone cut

            if (response.Authority.Count > 0)
            {
                bool authorityNotInZoneCut = false;
                string zoneCutEnd = "." + zoneCut;

                foreach (DnsResourceRecord authority in response.Authority)
                {
                    if ((authority.Type == DnsResourceRecordType.SOA) || (authority.Type == DnsResourceRecordType.NS))
                    {
                        if (!authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                        {
                            authorityNotInZoneCut = true;
                            break;
                        }
                    }
                }

                if (authorityNotInZoneCut)
                {
                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        switch (authority.Type)
                        {
                            case DnsResourceRecordType.SOA:
                            case DnsResourceRecordType.NS:
                                if (authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                                    newAuthority.Add(authority);

                                break;

                            case DnsResourceRecordType.RRSIG:
                                switch ((authority.RDATA as DnsRRSIGRecordData).TypeCovered)
                                {
                                    case DnsResourceRecordType.SOA:
                                    case DnsResourceRecordType.NS:
                                        if (authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                                            newAuthority.Add(authority);

                                        break;

                                    default:
                                        newAuthority.Add(authority);
                                        break;
                                }
                                break;

                            default:
                                newAuthority.Add(authority);
                                break;
                        }
                    }

                    return response.Clone(null, newAuthority);
                }
            }

            return response;
        }
    }
}