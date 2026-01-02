using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal static class RootHints
    {
        private static IReadOnlyList<NameServerAddress> _ipv4 = BuiltInIPv4();
        private static IReadOnlyList<NameServerAddress> _ipv6 = BuiltInIPv6();

        public static List<DnsResourceRecord> ROOT_TRUST_ANCHORS { get; private set; }

        static RootHints()
        {
            // Fire-and-forget refresh attempt (best-effort)
            _ = Task.Run(ReloadFromNamedRootAsync);
            _ = Task.Run(ReloadRootTrustAnchors);

        }

        public static IReadOnlyList<NameServerAddress> IPv4 => _ipv4;

        public static IReadOnlyList<NameServerAddress> IPv6 => _ipv6;

        public static List<NameServerAddress> GetShuffled(bool preferIPv6)
        {
            var list = new List<NameServerAddress>();

            if (preferIPv6)
            {
                list.AddRange(_ipv6);
                list.AddRange(_ipv4);

                list.Shuffle();
                list.Sort(ComparePreferIPv6);

                EnsureOneIpv4NearTop(list);
            }
            else
            {
                list.AddRange(_ipv4);
                list.Shuffle();
            }

            return list;
        }

        // -------------------------
        // Built-in static defaults
        // -------------------------

        private static IReadOnlyList<NameServerAddress> BuiltInIPv4() => new[]
        {
            new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")),
            new NameServerAddress("b.root-servers.net", IPAddress.Parse("170.247.170.2")),
            new NameServerAddress("c.root-servers.net", IPAddress.Parse("192.33.4.12")),
            new NameServerAddress("d.root-servers.net", IPAddress.Parse("199.7.91.13")),
            new NameServerAddress("e.root-servers.net", IPAddress.Parse("192.203.230.10")),
            new NameServerAddress("f.root-servers.net", IPAddress.Parse("192.5.5.241")),
            new NameServerAddress("g.root-servers.net", IPAddress.Parse("192.112.36.4")),
            new NameServerAddress("h.root-servers.net", IPAddress.Parse("198.97.190.53")),
            new NameServerAddress("i.root-servers.net", IPAddress.Parse("192.36.148.17")),
            new NameServerAddress("j.root-servers.net", IPAddress.Parse("192.58.128.30")),
            new NameServerAddress("k.root-servers.net", IPAddress.Parse("193.0.14.129")),
            new NameServerAddress("l.root-servers.net", IPAddress.Parse("199.7.83.42")),
            new NameServerAddress("m.root-servers.net", IPAddress.Parse("202.12.27.33"))
        };

        private static IReadOnlyList<NameServerAddress> BuiltInIPv6() => new[]
        {
            new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")),
            new NameServerAddress("b.root-servers.net", IPAddress.Parse("2801:1b8:10::b")),
            new NameServerAddress("c.root-servers.net", IPAddress.Parse("2001:500:2::c")),
            new NameServerAddress("d.root-servers.net", IPAddress.Parse("2001:500:2d::d")),
            new NameServerAddress("e.root-servers.net", IPAddress.Parse("2001:500:a8::e")),
            new NameServerAddress("f.root-servers.net", IPAddress.Parse("2001:500:2f::f")),
            new NameServerAddress("g.root-servers.net", IPAddress.Parse("2001:500:12::d0d")),
            new NameServerAddress("h.root-servers.net", IPAddress.Parse("2001:500:1::53")),
            new NameServerAddress("i.root-servers.net", IPAddress.Parse("2001:7fe::53")),
            new NameServerAddress("j.root-servers.net", IPAddress.Parse("2001:503:c27::2:30")),
            new NameServerAddress("k.root-servers.net", IPAddress.Parse("2001:7fd::1")),
            new NameServerAddress("l.root-servers.net", IPAddress.Parse("2001:500:9f::42")),
            new NameServerAddress("m.root-servers.net", IPAddress.Parse("2001:dc3::35"))
        };

        // ----------------------------------------
        // Optional live refresh from "named.root"
        // ----------------------------------------

        private static async Task ReloadFromNamedRootAsync()
        {
            try
            {
                var file = Path.Combine(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!,
                    "named.root");

                if (!File.Exists(file))
                    return;

                var zone = await ZoneFile.ReadZoneFileFromAsync(file);

                var ipv4 = new List<NameServerAddress>();
                var ipv6 = new List<NameServerAddress>();

                foreach (var ns in zone)
                {
                    if (ns.Type != DnsResourceRecordType.NS || ns.Name.Length != 0)
                        continue;

                    var name = ((DnsNSRecordData)ns.RDATA).NameServer.ToLowerInvariant();

                    foreach (var rr in zone)
                    {
                        if (!rr.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                            continue;

                        switch (rr.Type)
                        {
                            case DnsResourceRecordType.A:
                                ipv4.Add(new NameServerAddress(name, ((DnsARecordData)rr.RDATA).Address));
                                break;

                            case DnsResourceRecordType.AAAA:
                                ipv6.Add(new NameServerAddress(name, ((DnsAAAARecordData)rr.RDATA).Address));
                                break;
                        }
                    }
                }

                if (ipv4.Count > 0)
                    _ipv4 = ipv4;

                if (ipv6.Count > 0)
                    _ipv6 = ipv6;
            }
            catch
            {
                // swallow failures — resolver must remain functional
            }
        }


        public static void ReloadRootTrustAnchors()
        {
            string rootTrustXmlFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "root-anchors.xml");

            XmlDocument rootTrustXml = new XmlDocument();
            rootTrustXml.Load(rootTrustXmlFile);

            XmlNamespaceManager nsMgr = new XmlNamespaceManager(rootTrustXml.NameTable);
            XmlNodeList nodeList = rootTrustXml.SelectNodes("//TrustAnchor/KeyDigest", nsMgr);

            const string dateFormat = "yyyy-MM-ddTHH:mm:sszzz";
            List<DnsResourceRecord> rootTrustAnchors = new List<DnsResourceRecord>();

            foreach (XmlNode keyDigestNode in nodeList)
            {
                DateTime validFrom = DateTime.MinValue;
                DateTime validUntil = DateTime.MinValue;

                foreach (XmlAttribute attribute in keyDigestNode.Attributes)
                {
                    switch (attribute.Name)
                    {
                        case "validFrom":
                            validFrom = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.CurrentCulture);
                            break;

                        case "validUntil":
                            validUntil = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.CurrentCulture);
                            break;
                    }
                }

                if ((validFrom != DateTime.MinValue) && (validFrom > DateTime.UtcNow))
                    continue;

                if ((validUntil != DateTime.MinValue) && (validUntil < DateTime.UtcNow))
                    continue;

                ushort keyTag = 0;
                DnssecAlgorithm algorithm = DnssecAlgorithm.Unknown;
                DnssecDigestType digestType = DnssecDigestType.Unknown;
                string? digest = null;

                foreach (XmlNode childNode in keyDigestNode.ChildNodes)
                {
                    switch (childNode.Name.ToLowerInvariant())
                    {
                        case "keytag":
                            keyTag = ushort.Parse(childNode.InnerText);
                            break;

                        case "algorithm":
                            algorithm = (DnssecAlgorithm)byte.Parse(childNode.InnerText);
                            break;

                        case "digesttype":
                            digestType = (DnssecDigestType)byte.Parse(childNode.InnerText);
                            break;

                        case "digest":
                            digest = childNode.InnerText;
                            break;
                    }
                }

                rootTrustAnchors.Add(new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, Convert.FromHexString(digest))));
            }

            ROOT_TRUST_ANCHORS = rootTrustAnchors;
        }

        private static int ComparePreferIPv6(NameServerAddress a, NameServerAddress b)
        {
            var afA = a.IPEndPoint.AddressFamily;
            var afB = b.IPEndPoint.AddressFamily;
            return afA.CompareTo(afB);
        }

        private static void EnsureOneIpv4NearTop(List<NameServerAddress> servers)
        {
            if (servers.Count < 3)
                return;

            for (int i = 0; i < servers.Count; i++)
            {
                if (servers[i].IsIPEndPointStale)
                    continue;

                if (servers[i].IPEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (i < 2)
                        return;

                    (servers[i], servers[1]) = (servers[1], servers[i]);
                    return;
                }
            }
        }
    }
}
