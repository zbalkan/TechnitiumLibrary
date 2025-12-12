/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Proxy
{
    enum NetProxyBypassItemType
    {
        Unknown = 0,
        IpAddress = 1,
        NetworkAddress = 2,
        DomainName = 3
    }

    public class NetProxyBypassItem
    {
        #region variables

        readonly string _originalValue;

        readonly NetProxyBypassItemType _type;

        readonly IPAddress _ipAddress;
        readonly NetworkAddress _networkAddress;
        readonly string _domainName;

        #endregion

        #region constructor

        public NetProxyBypassItem(string value)
        {
            _originalValue = value;

            if (IPAddress.TryParse(value, out _ipAddress))
            {
                _type = NetProxyBypassItemType.IpAddress;
            }
            else if (NetworkAddress.TryParse(value, out _networkAddress))
            {
                switch (_networkAddress.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        if (_networkAddress.PrefixLength == 32)
                        {
                            _type = NetProxyBypassItemType.IpAddress;
                            _ipAddress = _networkAddress.Address;
                            _networkAddress = null;
                            return;
                        }

                        break;

                    case AddressFamily.InterNetworkV6:
                        if (_networkAddress.PrefixLength == 128)
                        {
                            _type = NetProxyBypassItemType.IpAddress;
                            _ipAddress = _networkAddress.Address;
                            _networkAddress = null;
                            return;
                        }

                        break;
                }

                _type = NetProxyBypassItemType.NetworkAddress;
            }
            else if (DnsClient.IsDomainNameValid(value))
            {
                _type = NetProxyBypassItemType.DomainName;
                _domainName = value;
            }
            else
            {
                throw new NetProxyException("Invalid proxy bypass value: " + value);
            }
        }

        #endregion

        #region public

        public bool IsMatching(EndPoint ep)
        {
            return _type switch
            {
                NetProxyBypassItemType.IpAddress =>
                    ep is IPEndPoint ip1 && _ipAddress.Equals(ip1.Address),

                NetProxyBypassItemType.NetworkAddress =>
                    ep is IPEndPoint ip2 && _networkAddress.Contains(ip2.Address),

                NetProxyBypassItemType.DomainName =>
                    IsDomainMatch(ep),

                _ => throw new NotSupportedException("NetProxyBypassItemType not supported.")
            };
        }

        private bool IsDomainMatch(EndPoint ep)
        {
            if (_domainName.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                return IsLocalhostMatch(ep);

            if (ep is not DomainEndPoint dep)
                return false;

            string matchDomainName = dep.Address;

            return _domainName.Length == matchDomainName.Length
                ? _domainName.Equals(matchDomainName, StringComparison.OrdinalIgnoreCase)
                : matchDomainName.EndsWith("." + _domainName, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsLocalhostMatch(EndPoint ep)
        {
            return ep switch
            {
                IPEndPoint ip => IPAddress.IsLoopback(ip.Address),
                DomainEndPoint dep => dep.Address.Equals("localhost", StringComparison.OrdinalIgnoreCase),
                _ => false
            };
        }

        public override string ToString()
        {
            return _originalValue;
        }

        #endregion

        #region variables

        public string Value
        { get { return _originalValue; } }

        #endregion
    }
}
