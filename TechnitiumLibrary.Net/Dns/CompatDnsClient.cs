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

using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;


namespace TechnitiumLibrary.Net.Dns
{
    public sealed class CompatDnsClient : IDnsClient
    {
        private readonly RecursiveResolver _resolver;

        public IDnsCache Cache { get; set; }
        public NetProxy Proxy { get; set; }
        public bool DnssecValidation { get; set; } = true;

        public CompatDnsClient(bool preferIPv6)
        {
            var config = new ResolverConfig
            {
                PreferIPv6 = preferIPv6,
                DnssecValidation = true,
                QNameMinimization = true,
                Concurrency = 2,
                Retries = 3,
                Timeout = 5000
            };

            _resolver = new RecursiveResolver(config, cache: null);
        }

        public Task<DnsDatagram> ResolveAsync(
            DnsQuestionRecord question,
            CancellationToken cancellationToken = default)
        {
            return _resolver.ResolveAsync(
                question,
                cache: Cache,
                qnameMinimization: true,
                dnssecValidation: DnssecValidation,
                eDnsClientSubnet: null,
                minimalResponse: false,
                asyncNsResolution: false,
                rawResponses: null,
                cancellationToken);
        }
    }

}
