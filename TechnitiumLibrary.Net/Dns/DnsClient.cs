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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;


namespace TechnitiumLibrary.Net.Dns
{
    public enum DnsTransportProtocol : byte
    {
        Udp = 0,
        Tcp = 1,
        Tls = 2, //RFC-7858
        Https = 3, //RFC-8484
        HttpsJson = 4, //Google
        Quic = 5, //RFC 9250
        UdpProxy = 253, //PROXY Protocol over UDP
        TcpProxy = 254 //PROXY Protocol over TCP
    }

    public partial class DnsClient : IDnsClient
    {
        #region variables

        internal const int MAX_CNAME_HOPS = 16;
        internal const int MAX_NSEC3_ITERATIONS = 100;
        //CVE-2023-50868 NSEC3 closest encloser proof DoS mitigation
        internal const int NSEC3_MAX_HASHES_PER_SUSPENSION = 8;

        //task will suspend after max NSEC3 compute hash calls
        internal const int NSEC3_MAX_SUSPENSIONS_PER_RESPONSE = 16;

        const int KEY_TRAP_MAX_CRYPTO_FAILURES = 16;
        //CVE-2023-50387 KeyTrap mitigation
        internal const int KEY_TRAP_MAX_KEY_TAG_COLLISIONS = 4;

        //HashTrap mitigation by limiting key collisions
        //mitigation by limiting cryptographic failures per resolution
        internal const int KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION = 8;

        //task will suspend after max RRSET validations
        internal const int KEY_TRAP_MAX_SUSPENSIONS_PER_RESPONSE = 16;

        internal const int MAX_DELEGATION_HOPS = 16;
        //max NS referrals to follow
        //max CNAMEs to follow
        internal const int MAX_NS_TO_QUERY_PER_REFERRAL = 16;

        internal const int NS_RESOLUTION_TIMEOUT = 60000;

        //max NS to query per referral response to mitigate NRDelegationAttack and NXNSAttack
        //max iterations allowed for NSEC3 [RFC 9276]

        //task will stop RRSET validation after max suspensions for the response

        //verify signature for all records in response
        readonly DnssecValidateSignatureParameters _parameters = new DnssecValidateSignatureParameters();

        //task will stop NSEC3 proof validation after max suspensions for the response
        readonly IReadOnlyList<NameServerAddress> _servers;

        readonly bool _advancedForwardingClientSubnet;
        readonly IDnsCache _cache;
        readonly int _concurrency = 2;
        //this feature is used by Advanced Forwarding app to cache response per network group
        readonly string _conditionalForwardingZoneCut;

        readonly bool _dnssecValidation;
        readonly NetworkAddress _eDnsClientSubnet;
        readonly bool _preferIPv6;
        readonly NetProxy _proxy;
        readonly bool _randomizeName;
        readonly int _retries = 2;
        readonly int _timeout = 2000;
        readonly Dictionary<string, IReadOnlyList<DnsResourceRecord>> _trustAnchors;
        readonly ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;

        private static readonly ResolverConfig _defaultConfig = new()
        {
            Proxy = null,
            PreferIPv6 = false,
            RandomizeName = true,
            QNameMinimization = true,
            DnssecValidation = true,
            UdpPayloadSize = 1232,
            Retries = 3,
            Timeout = 5000,
            Concurrency = 2,
            MaxStackCount = 32
        };

        private static readonly RecursiveResolver _resolver =
            new(_defaultConfig, cache: null);

        static readonly Lazy<DnsClient> instance = new Lazy<DnsClient>(() => new DnsClient());

        #endregion


        #region constructor
        public DnsClient(Uri dohEndPoint)
        {
            _servers = [new NameServerAddress(dohEndPoint)];
        }

        public DnsClient(Uri[] dohEndPoints)
        {
            if (dohEndPoints.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] servers = new NameServerAddress[dohEndPoints.Length];

            for (int i = 0; i < dohEndPoints.Length; i++)
                servers[i] = new NameServerAddress(dohEndPoints[i]);

            _servers = servers;
        }

        public DnsClient(bool preferIPv6 = false)
        {
            _preferIPv6 = preferIPv6;

            IReadOnlyList<IPAddress> systemDnsServers = Helpers.GetSystemDnsServers(_preferIPv6);
            if (systemDnsServers.Count == 0)
                throw new DnsClientException("No DNS servers were found configured on this system.");

            NameServerAddress[] servers = new NameServerAddress[systemDnsServers.Count];

            for (int i = 0; i < systemDnsServers.Count; i++)
                servers[i] = new NameServerAddress(systemDnsServers[i]);

            _servers = servers;
        }

        public DnsClient(IPAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] nameServers = new NameServerAddress[servers.Length];

            for (int i = 0; i < servers.Length; i++)
                nameServers[i] = new NameServerAddress(servers[i]);

            _servers = nameServers;
        }

        public DnsClient(IPAddress server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(EndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(string addresses)
            : this(addresses.Split(NameServerAddress.Parse, ','))
        { }

        public DnsClient(params string[] addresses)
            : this(addresses.Convert(NameServerAddress.Parse))
        { }

        public DnsClient(string address, DnsTransportProtocol protocol)
            : this(NameServerAddress.Parse(address, protocol))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = [server];
        }

        public DnsClient(params NameServerAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        public DnsClient(IReadOnlyList<NameServerAddress> servers)
        {
            if (servers.Count == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }
        #endregion

        #region public

        public static DnsClient Instance => instance.Value;

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            return _resolver.ResolveAsync(
              question,
              cache: null,
              qnameMinimization: _defaultConfig.QNameMinimization,
              dnssecValidation: _defaultConfig.DnssecValidation,
              eDnsClientSubnet: null,
              minimalResponse: false,
              asyncNsResolution: false,
              rawResponses: null,
              cancellationToken);
        }

        public Task<DnsDatagram> RecursiveResolveQueryAsync(DnsQuestionRecord question, IDnsCache? cache = null, NetProxy? proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress? eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, CancellationToken cancellationToken = default)
        {
            cache ??= new DnsCache();

            return ResolveQueryAsync(question, delegate (DnsQuestionRecord q)
            {
                return RecursiveResolveAsync(q, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, true, cancellationToken: cancellationToken);
            });
        }

        public async Task<IReadOnlyList<IPAddress>> RecursiveResolveIPAsync(
    string domain,
    IDnsCache? cache = null,
    NetProxy? proxy = null,
    bool preferIPv6 = false,
    ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE,
    bool randomizeName = false,
    bool qnameMinimization = false,
    bool dnssecValidation = false,
    NetworkAddress? eDnsClientSubnet = null,
    int retries = 2,
    int timeout = 2000,
    int concurrency = 2,
    int maxStackCount = 16,
    CancellationToken cancellationToken = default)
        {
            cache ??= new DnsCache();

            // launch AAAA in parallel only when v6 preferred
            Task<DnsDatagram>? ipv6Task =
                preferIPv6
                    ? RecursiveResolveAsync(
                        new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN),
                        cache,
                        proxy,
                        preferIPv6,
                        udpPayloadSize,
                        randomizeName,
                        qnameMinimization,
                        dnssecValidation,
                        eDnsClientSubnet,
                        retries,
                        timeout,
                        concurrency,
                        maxStackCount,
                        minimalResponse: false,
                        asyncNsResolution: false,
                        rawResponses: null,
                        cancellationToken)
                    : null;

            // always resolve IPv4
            var ipv4Response = await RecursiveResolveAsync(
                new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN),
                cache,
                proxy,
                preferIPv6,
                udpPayloadSize,
                randomizeName,
                qnameMinimization,
                dnssecValidation,
                eDnsClientSubnet,
                retries,
                timeout,
                concurrency,
                maxStackCount,
                minimalResponse: false,
                asyncNsResolution: false,
                rawResponses: null,
                cancellationToken);

            var ipv4Addresses = ParseResponseA(ipv4Response);

            IReadOnlyList<IPAddress>? ipv6Addresses = null;

            if (preferIPv6 && ipv6Task is not null)
                ipv6Addresses = ParseResponseAAAA(await ipv6Task);

            var result = new List<IPAddress>(
                (ipv6Addresses?.Count ?? 0) + ipv4Addresses.Count);

            if (preferIPv6 && ipv6Addresses is not null)
                result.AddRange(ipv6Addresses);

            result.AddRange(ipv4Addresses);

            return result;
        }

        public async Task<DnsDatagram> RecursiveResolveAsync(
    DnsQuestionRecord question,
    IDnsCache? cache = null,
    NetProxy? proxy = null,
    bool preferIPv6 = false,
    ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE,
    bool randomizeName = false,
    bool qnameMinimization = false,
    bool dnssecValidation = false,
    NetworkAddress? eDnsClientSubnet = null,
    int retries = 2,
    int timeout = 2000,
    int concurrency = 2,
    int maxStackCount = 16,
    bool minimalResponse = false,
    bool asyncNsResolution = false,
    List<DnsDatagram>? rawResponses = null,
    CancellationToken cancellationToken = default)
        {
            // Preserve legacy EDNS + DNSSEC guard
            if ((udpPayloadSize < 512) &&
                (dnssecValidation || (eDnsClientSubnet is not null)))
                throw new ArgumentOutOfRangeException(
                    nameof(udpPayloadSize),
                    "EDNS cannot be disabled by setting UDP payload size to less than 512 when DNSSEC validation or EDNS Client Subnet is enabled.");

            // Preserve legacy cache semantics
            cache ??= new DnsCache();

            // Preserve QNAME minimization semantics
            if (qnameMinimization)
            {
                question = question.Clone();
                question.ZoneCut = "";
            }

            var config = new ResolverConfig
            {
                Proxy = proxy,
                PreferIPv6 = preferIPv6,
                RandomizeName = randomizeName,
                QNameMinimization = qnameMinimization,
                DnssecValidation = dnssecValidation,
                UdpPayloadSize = udpPayloadSize,
                Retries = retries,
                Timeout = timeout,
                Concurrency = concurrency,
                MaxStackCount = maxStackCount
            };

            var resolver = new RecursiveResolver(config, cache);

            return await resolver.ResolveAsync(
                question,
                cache,
                qnameMinimization,
                dnssecValidation,
                eDnsClientSubnet,
                minimalResponse,
                asyncNsResolution,
                rawResponses,
                cancellationToken);
        }


        #endregion public

        #region static

        public static IReadOnlyList<IPAddress> ParseResponseA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                    ipAddresses.Add((record.RDATA as DnsARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<IPAddress> ParseResponseAAAA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.AAAA:
                                    ipAddresses.Add((record.RDATA as DnsAAAARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsDSRecordData> ParseResponseDS(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsDSRecordData>();

                    List<DnsDSRecordData> dsRecords = new List<DnsDSRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.DS:
                                    dsRecords.Add(record.RDATA as DnsDSRecordData);
                                    break;
                            }
                        }
                    }

                    return dsRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponseMX(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<DnsMXRecordData> mxRecords = new List<DnsMXRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.MX:
                                    mxRecords.Add(record.RDATA as DnsMXRecordData);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    if (mxRecords.Count > 0)
                    {
                        //sort by mx preference
                        mxRecords.Sort();

                        string[] mxEntries = new string[mxRecords.Count];

                        for (int i = 0; i < mxEntries.Length; i++)
                            mxEntries[i] = mxRecords[i].Exchange;

                        return mxEntries;
                    }

                    return Array.Empty<string>();

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponsePTR(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> values = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.PTR:
                                    values.Add((record.RDATA as DnsPTRRecordData).Domain);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return values;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static DnsSOARecordData? ParseResponseSOA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return null;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.SOA:
                                    return record.RDATA as DnsSOARecordData;
                            }
                        }
                    }

                    return null;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsTLSARecordData>? ParseResponseTLSA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsTLSARecordData>();

                    List<DnsTLSARecordData> tlsaRecords = new List<DnsTLSARecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.DnssecStatus != DnssecStatus.Secure)
                            continue;

                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TLSA:
                                    DnsTLSARecordData? tlsa = record.RDATA as DnsTLSARecordData;

                                    switch (tlsa.CertificateUsage)
                                    {
                                        case DnsTLSACertificateUsage.PKIX_TA:
                                        case DnsTLSACertificateUsage.PKIX_EE:
                                        case DnsTLSACertificateUsage.DANE_TA:
                                        case DnsTLSACertificateUsage.DANE_EE:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    switch (tlsa.Selector)
                                    {
                                        case DnsTLSASelector.Cert:
                                        case DnsTLSASelector.SPKI:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    switch (tlsa.MatchingType)
                                    {
                                        case DnsTLSAMatchingType.Full:
                                        case DnsTLSAMatchingType.SHA2_256:
                                        case DnsTLSAMatchingType.SHA2_512:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    if (tlsa.CertificateAssociationData.Length == 0)
                                        continue; //unusable

                                    tlsaRecords.Add(tlsa);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return tlsaRecords;

                case DnsResponseCode.NxDomain:
                    return null;

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponseTXT(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> txtRecords = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TXT:
                                    txtRecords.Add((record.RDATA as DnsTXTRecordData).GetText());
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return txtRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsZONEMDRecordData> ParseResponseZONEMD(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return [];

                    List<DnsZONEMDRecordData> zonemdRecords = new List<DnsZONEMDRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.ZONEMD:
                                    zonemdRecords.Add(record.RDATA as DnsZONEMDRecordData);
                                    break;
                            }
                        }
                    }

                    return zonemdRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static async Task<IReadOnlyList<IPAddress>> ResolveIPAsync(IDnsClient dnsClient, string domain, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            Task<DnsDatagram>? ipv6Task = preferIPv6 ? dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken) : null;
            Task<DnsDatagram> ipv4Task = dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cancellationToken);

            IReadOnlyList<IPAddress>? ipv6Addresses = preferIPv6 ? ParseResponseAAAA(await ipv6Task) : null;
            IReadOnlyList<IPAddress> ipv4Addresses = ParseResponseA(await ipv4Task);

            List<IPAddress> ipAddresses = new List<IPAddress>((ipv6Addresses is null ? 0 : ipv6Addresses.Count) + ipv4Addresses.Count);

            if (preferIPv6)
                ipAddresses.AddRange(ipv6Addresses);

            ipAddresses.AddRange(ipv4Addresses);

            return ipAddresses;
        }

        public static async Task<IReadOnlyList<string>> ResolveMXAsync(IDnsClient dnsClient, string domain, bool resolveIP = false, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                //host is valid ip address
                return new string[] { domain };
            }

            DnsDatagram response = await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN), cancellationToken);
            IReadOnlyList<string> mxEntries = ParseResponseMX(response);

            if (!resolveIP)
                return mxEntries;

            //resolve IP addresses
            List<string> mxAddresses = new List<string>(preferIPv6 ? mxEntries.Count * 2 : mxEntries.Count);

            //check glue records
            foreach (string mxEntry in mxEntries)
            {
                bool glueRecordFound = false;

                foreach (DnsResourceRecord record in response.Additional)
                {
                    switch (record.DnssecStatus)
                    {
                        case DnssecStatus.Disabled:
                        case DnssecStatus.Secure:
                        case DnssecStatus.Insecure:
                            break;

                        default:
                            continue;
                    }

                    if (record.Name.Equals(mxEntry, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                mxAddresses.Add((record.RDATA as DnsARecordData).Address.ToString());
                                glueRecordFound = true;
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (preferIPv6)
                                {
                                    mxAddresses.Add((record.RDATA as DnsAAAARecordData).Address.ToString());
                                    glueRecordFound = true;
                                }
                                break;
                        }
                    }
                }

                if (!glueRecordFound)
                {
                    try
                    {
                        IReadOnlyList<IPAddress> ipList = await ResolveIPAsync(dnsClient, mxEntry, preferIPv6, cancellationToken);

                        foreach (IPAddress ip in ipList)
                            mxAddresses.Add(ip.ToString());
                    }
                    catch (DnsClientException)
                    { }
                }
            }

            return mxAddresses;
        }


        #endregion static

        #region internal
        internal async Task<DnsDatagram> InternalResolveAsync(
                                            DnsDatagram request,
                                            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            Exception? last = null;

            for (int attempt = 0; attempt <= _retries; attempt++)
            {
                foreach (var server in _servers)
                {
                    try
                    {
                        return await SendAsync(server, request, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        last = ex;
                    }
                }
            }

            throw last!;
        }

        #endregion internal

        #region private
        private static async Task<DnsDatagram> ResolveQueryAsync(
                      DnsQuestionRecord question,
                      Func<DnsQuestionRecord, Task<DnsDatagram>> resolveAsync)
        {
            var response = await resolveAsync(question);

            // never fabricate REFUSED — let resolver decide failure semantics
            return response ?? throw new DnsClientException(
                $"Resolver returned null for {question}");
        }


        private async Task<DnsDatagram> SendUdpAsync(
                                        NameServerAddress server,
                                        DnsDatagram request,
                                        CancellationToken cancellationToken)
        {
            using var socket = new Socket(
                server.IPEndPoint!.AddressFamily,
                SocketType.Dgram,
                ProtocolType.Udp);

            socket.SendTimeout = _timeout;
            socket.ReceiveTimeout = _timeout;

            // serialize request
            using var ms = new MemoryStream(4096);
            request.WriteTo(ms);
            var buffer = ms.ToArray();

            var recvBuffer = new byte[_udpPayloadSize];
            var received = await socket.UdpQueryAsync(
                new ArraySegment<byte>(buffer),
                new ArraySegment<byte>(recvBuffer),
                server.IPEndPoint,
                timeout: _timeout,
                retries: _retries + 1,
                expBackoffTimeout: false,
                isResponseValid: null,
                cancellationToken: cancellationToken);

            using var rs = new MemoryStream(recvBuffer, 0, received);
            var response = DnsDatagram.ReadFrom(rs);

            response.SetMetadata(server);
            return response;
        }

        private async Task<DnsDatagram> SendTcpAsync(
                                        NameServerAddress server,
                                        DnsDatagram request,
                                        CancellationToken cancellationToken)
        {
            using var tcp = new Socket(
                server.IPEndPoint!.AddressFamily,
                SocketType.Stream,
                ProtocolType.Tcp);

            tcp.Connect(server.IPEndPoint, _timeout);

            using var ns = new NetworkStream(tcp, ownsSocket: false);
            using var ms = new MemoryStream(4096);

            await request.WriteToTcpAsync(ns, ms, cancellationToken);

            var response = await DnsDatagram.ReadFromTcpAsync(
                ns,
                ms,
                cancellationToken);

            response.SetMetadata(server);
            return response;
        }
        private async Task<DnsDatagram> SendAsync(
                                        NameServerAddress server,
                                        DnsDatagram request,
                                        CancellationToken cancellationToken)
        {
            var response = await SendUdpAsync(server, request, cancellationToken);

            if (response.Truncation)
                response = await SendTcpAsync(server, request, cancellationToken);

            return response;
        }
        #endregion

    }

}
