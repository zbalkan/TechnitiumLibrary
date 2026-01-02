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
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net.Dns
{
    public partial class DnsClient
    {
        public static class Helpers
        {
            static readonly IdnMapping _idnMapping = new IdnMapping() { AllowUnassigned = true };

            public static IReadOnlyList<IPAddress> GetSystemDnsServers(bool preferIPv6 = false)
            {
                List<IPAddress> dnsAddresses = new List<IPAddress>();

                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    foreach (IPAddress dnsAddress in nic.GetIPProperties().DnsAddresses)
                    {
                        if (!preferIPv6 && (dnsAddress.AddressFamily == AddressFamily.InterNetworkV6))
                            continue;

                        if ((dnsAddress.AddressFamily == AddressFamily.InterNetworkV6) && dnsAddress.IsIPv6SiteLocal)
                            continue;

                        if (!dnsAddresses.Contains(dnsAddress))
                            dnsAddresses.Add(dnsAddress);
                    }
                }

                return dnsAddresses;
            }

            public static string ConvertDomainNameToAscii(string domain)
            {
                return _idnMapping.GetAscii(domain);
            }

            public static string ConvertDomainNameToUnicode(string domain)
            {
                return _idnMapping.GetUnicode(domain);
            }

            public static bool IsDomainNameUnicode(string domain)
            {
                foreach (char c in domain)
                {
                    if (!char.IsAscii(c))
                        return true;
                }

                return false;
            }

            public static bool IsDomainNameValid(string domain, bool throwException = false)
            {
                if (domain is null)
                {
                    if (throwException)
                        throw new ArgumentNullException(nameof(domain));

                    return false;
                }

                if (domain.Length == 0)
                    return true; //domain is root zone

                if (domain.Length > 255)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

                    return false;
                }

                int labelStart = 0;
                int labelEnd;
                int labelLength;
                int labelChar;
                int i;

                do
                {
                    labelEnd = domain.IndexOf('.', labelStart);
                    if (labelEnd < 0)
                        labelEnd = domain.Length;

                    labelLength = labelEnd - labelStart;

                    if (labelLength == 0)
                    {
                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                        return false;
                    }

                    if (labelLength > 63)
                    {
                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                        return false;
                    }

                    if (domain[labelStart] == '-')
                    {
                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                        return false;
                    }

                    if (domain[labelEnd - 1] == '-')
                    {
                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                        return false;
                    }

                    if (labelLength != 1 || domain[labelStart] != '*')
                    {
                        for (i = labelStart; i < labelEnd; i++)
                        {
                            labelChar = domain[i];

                            if ((labelChar >= 97) && (labelChar <= 122)) //[a-z]
                                continue;

                            if ((labelChar >= 65) && (labelChar <= 90)) //[A-Z]
                                continue;

                            if ((labelChar >= 48) && (labelChar <= 57)) //[0-9]
                                continue;

                            if (labelChar == 45) //[-]
                                continue;

                            if (labelChar == 95) //[_]
                                continue;

                            if (labelChar == 47) //[/]
                                continue;

                            if (throwException)
                                throw new DnsClientException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                            return false;
                        }
                    }

                    labelStart = labelEnd + 1;
                }
                while (labelEnd < domain.Length);

                return true;
            }

            public static bool TryConvertDomainNameToUnicode(string domain, out string idn)
            {
                if (domain.Contains("xn--", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        idn = _idnMapping.GetUnicode(domain);
                        return true;
                    }
                    catch
                    { }
                }

                idn = null;
                return false;
            }
        }

    }
}