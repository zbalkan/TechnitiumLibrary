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
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TechnitiumLibrary.Net
{
    public static class IPAddressExtensions
    {
        #region static

        public static IPAddress ReadFrom(BinaryReader bR)
        {
            return ReadFrom(bR.BaseStream);
        }

        public static IPAddress ReadFrom(Stream s)
        {
            switch (s.ReadByte())
            {
                case 1:
                    Span<byte> ipv4 = stackalloc byte[4];
                    s.ReadExactly(ipv4);
                    return new IPAddress(ipv4);

                case 2:
                    Span<byte> ipv6 = stackalloc byte[16];
                    s.ReadExactly(ipv6);
                    return new IPAddress(ipv6);

                case -1:
                    throw new EndOfStreamException();

                default:
                    throw new NotSupportedException("Address Family not supported.");
            }
        }

        public static void WriteTo(this IPAddress address, BinaryWriter bW)
        {
            WriteTo(address, bW.BaseStream);
        }

        public static void WriteTo(this IPAddress address, Stream s)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    s.WriteByte(1);

                    Span<byte> ipv4 = stackalloc byte[4];
                    if (!address.TryWriteBytes(ipv4, out _))
                        throw new InvalidOperationException();

                    s.Write(ipv4);
                    break;

                case AddressFamily.InterNetworkV6:
                    s.WriteByte(2);

                    Span<byte> ipv6 = stackalloc byte[16];
                    if (!address.TryWriteBytes(ipv6, out _))
                        throw new InvalidOperationException();

                    s.Write(ipv6);
                    break;

                default:
                    throw new NotSupportedException("Address Family not supported.");
            }
        }

        public static uint ConvertIpToNumber(this IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address Family not supported.");

            Span<byte> addr = stackalloc byte[4];
            if (!address.TryWriteBytes(addr, out _))
                throw new InvalidOperationException();

            return BinaryPrimitives.ReadUInt32BigEndian(addr);
        }

        public static IPAddress ConvertNumberToIp(uint address)
        {
            Span<byte> addr = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(addr, address);
            return new IPAddress(addr);
        }

        public static int GetSubnetMaskWidth(this IPAddress subnetMask)
        {
            if (subnetMask.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address Family not supported.");

            uint subnetMaskNumber = subnetMask.ConvertIpToNumber();
            int subnetMaskWidth = 0;

            while (subnetMaskNumber > 0u)
            {
                subnetMaskNumber <<= 1;
                subnetMaskWidth++;
            }

            return subnetMaskWidth;
        }

        public static IPAddress GetSubnetMask(int prefixLength)
        {
            if (prefixLength > 32)
                throw new ArgumentOutOfRangeException(nameof(prefixLength), "Invalid network prefix.");

            if (prefixLength == 0)
                return IPAddress.Any;

            Span<byte> subnetMaskBuffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(subnetMaskBuffer, 0xFFFFFFFFu << (32 - prefixLength));

            return new IPAddress(subnetMaskBuffer);
        }


        private static IPAddress MaskAddress(ReadOnlySpan<byte> addressBytes, int prefixLength)
        {
            Span<byte> output = stackalloc byte[addressBytes.Length];
            output.Clear(); // IMPORTANT: zero out host part by default

            int fullBytes = prefixLength / 8;
            int remainderBits = prefixLength % 8;

            if (fullBytes > 0)
                addressBytes[..fullBytes].CopyTo(output);

            if (remainderBits > 0)
            {
                // Mask the next byte, keeping only the top 'remainderBits'
                byte mask = (byte)(0xFF << (8 - remainderBits));
                output[fullBytes] = (byte)(addressBytes[fullBytes] & mask);
            }

            return new IPAddress(output);
        }
        public static IPAddress GetNetworkAddress(this IPAddress address, int prefixLength)
        {
            if (address is null)
                throw new ArgumentNullException(nameof(address));
            if (prefixLength < 0)
                throw new ArgumentOutOfRangeException(nameof(prefixLength), "Prefix length cannot be negative.");

            int maxBits, byteCount;

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    maxBits = 32; byteCount = 4; break;
                case AddressFamily.InterNetworkV6:
                    maxBits = 128; byteCount = 16; break;
                default:
                    throw new NotSupportedException("Address Family not supported.");
            }

            if (prefixLength == maxBits)
                return address;

            if (prefixLength > maxBits)
                throw new ArgumentOutOfRangeException(nameof(prefixLength), "Invalid network prefix.");

            Span<byte> bytes = stackalloc byte[byteCount];
            if (!address.TryWriteBytes(bytes, out _))
                throw new InvalidOperationException("Failed to serialize IP address bytes.");

            return MaskAddress(bytes, prefixLength);
        }

        public static IPAddress MapToIPv6(this IPAddress address, NetworkAddress ipv6Prefix)
        {
            //RFC 6052 section 2

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return address;

            switch (ipv6Prefix.PrefixLength)
            {
                case 32:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.CopyTo(ipv6Buffer.Slice(4));

                        return new IPAddress(ipv6Buffer);
                    }

                case 40:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.Slice(0, 3).CopyTo(ipv6Buffer.Slice(5));
                        ipv4Buffer.Slice(3, 1).CopyTo(ipv6Buffer.Slice(9));

                        return new IPAddress(ipv6Buffer);
                    }

                case 48:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.Slice(0, 2).CopyTo(ipv6Buffer.Slice(6));
                        ipv4Buffer.Slice(2, 2).CopyTo(ipv6Buffer.Slice(9));

                        return new IPAddress(ipv6Buffer);
                    }

                case 56:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.Slice(0, 1).CopyTo(ipv6Buffer.Slice(7));
                        ipv4Buffer.Slice(1, 3).CopyTo(ipv6Buffer.Slice(9));

                        return new IPAddress(ipv6Buffer);
                    }

                case 64:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.CopyTo(ipv6Buffer.Slice(9));

                        return new IPAddress(ipv6Buffer);
                    }

                case 96:
                    {
                        Span<byte> ipv4Buffer = stackalloc byte[4];
                        if (!address.TryWriteBytes(ipv4Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!ipv6Prefix.Address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        ipv4Buffer.CopyTo(ipv6Buffer.Slice(12));

                        return new IPAddress(ipv6Buffer);
                    }

                default:
                    throw new NotSupportedException("IPv4-embedded IPv6 address format supports only the following prefixes: 32, 40, 48, 56, 64, or 96.");
            }
        }

        public static IPAddress MapToIPv4(this IPAddress address, int prefixLength)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return address;

            switch (prefixLength)
            {
                case 32:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        return new IPAddress(ipv6Buffer.Slice(4, 4));
                    }

                case 40:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv4Buffer = stackalloc byte[4];

                        ipv6Buffer.Slice(5, 3).CopyTo(ipv4Buffer);
                        ipv6Buffer.Slice(9, 1).CopyTo(ipv4Buffer.Slice(3));

                        return new IPAddress(ipv4Buffer);
                    }

                case 48:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv4Buffer = stackalloc byte[4];

                        ipv6Buffer.Slice(6, 2).CopyTo(ipv4Buffer);
                        ipv6Buffer.Slice(9, 2).CopyTo(ipv4Buffer.Slice(2));

                        return new IPAddress(ipv4Buffer);
                    }

                case 56:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        Span<byte> ipv4Buffer = stackalloc byte[4];

                        ipv6Buffer.Slice(7, 1).CopyTo(ipv4Buffer);
                        ipv6Buffer.Slice(9, 3).CopyTo(ipv4Buffer.Slice(1));

                        return new IPAddress(ipv4Buffer);
                    }

                case 64:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        return new IPAddress(ipv6Buffer.Slice(9, 4));
                    }

                case 96:
                    {
                        Span<byte> ipv6Buffer = stackalloc byte[16];
                        if (!address.TryWriteBytes(ipv6Buffer, out _))
                            throw new InvalidOperationException();

                        return new IPAddress(ipv6Buffer.Slice(12, 4));
                    }

                default:
                    throw new NotSupportedException("IPv4-embedded IPv6 address format supports only the following prefixes: 32, 40, 48, 56, 64, or 96.");
            }
        }

        public static string GetReverseDomain(this IPAddress address)
        {
            StringBuilder name = new StringBuilder();

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        Span<byte> ipBytes = stackalloc byte[4];

                        if (!address.TryWriteBytes(ipBytes, out _))
                            throw new InvalidOperationException();

                        for (int i = ipBytes.Length - 1; i >= 0; i--)
                            name.Append(ipBytes[i]).Append('.');

                        name.Append("in-addr.arpa");
                    }
                    break;

                case AddressFamily.InterNetworkV6:
                    {
                        Span<byte> ipBytes = stackalloc byte[16];

                        if (!address.TryWriteBytes(ipBytes, out _))
                            throw new InvalidOperationException();

                        for (int i = ipBytes.Length - 1; i >= 0; i--)
                            name.Append((ipBytes[i] & 0x0F).ToString("x")).Append('.').Append((ipBytes[i] >> 4).ToString("x")).Append('.');

                        name.Append("ip6.arpa");
                    }
                    break;

                default:
                    throw new NotSupportedException("Address Family not supported: " + address.AddressFamily.ToString());
            }

            return name.ToString();
        }

        public static IPAddress ParseReverseDomain(string ptrDomain)
        {
            if (TryParseReverseDomain(ptrDomain, out IPAddress address))
                return address;

            throw new NotSupportedException("Invalid reverse domain: " + ptrDomain);
        }

        public static bool TryParseReverseDomain(string ptrDomain, out IPAddress address)
        {
            if (ptrDomain.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
            {
                string[] segments = ptrDomain.Split('.');

                // Expected form: A.B.C.D.in-addr.arpa
                // → exactly 7 segments
                if (segments.Length != 6)
                {
                    address = null;
                    return false;
                }

                Span<byte> buffer = stackalloc byte[4];

                // Extract forward as standard IPv4 order
                // PTR:   A.B.C.D.in-addr.arpa
                // IP:    D.C.B.A
                for (int i = 0; i < 4; i++)
                {
                    if (!byte.TryParse(segments[3 - i], out buffer[i]))
                    {
                        address = null;
                        return false;
                    }
                }

                address = new IPAddress(buffer);
                return true;
            }
            else if (ptrDomain.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
            {
                //B.E.3.0.B.3.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.9.F.F.4.6.0.0.ip6.arpa
                //64:ff9b::8b3b:3eb

                string[] parts = ptrDomain.Split('.');
                Span<byte> buffer = stackalloc byte[16];
                byte p1, p2;

                for (int i = 0, j = parts.Length - 3; (i < 16) && (j > 0); i++, j -= 2)
                {
                    if (!byte.TryParse(parts[j], NumberStyles.HexNumber, null, out p1) || !byte.TryParse(parts[j - 1], NumberStyles.HexNumber, null, out p2))
                    {
                        address = null;
                        return false;
                    }

                    buffer[i] = (byte)(p1 << 4 | p2);
                }

                address = new IPAddress(buffer);
                return true;
            }
            else
            {
                address = null;
                return false;
            }
        }

        #endregion
    }
}
