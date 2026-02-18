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
using System.IO;
using System.Linq;
using System.Text.Json;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    //DNS Cookies
    //https://datatracker.ietf.org/doc/html/rfc7873
    //https://datatracker.ietf.org/doc/html/rfc9018

    public class EDnsCookieOptionData : EDnsOptionData
    {
        #region variables

        byte[] _clientCookie;
        byte[] _serverCookie;

        #endregion

        #region constructor

        public EDnsCookieOptionData(byte[] clientCookie, byte[] serverCookie = null)
        {
            if (clientCookie is null)
                throw new ArgumentNullException(nameof(clientCookie));

            if (clientCookie.Length != 8)
                throw new ArgumentException("Client cookie must be exactly 8 bytes.", nameof(clientCookie));

            if (serverCookie is not null)
            {
                if (serverCookie.Length < 8 || serverCookie.Length > 32)
                    throw new ArgumentException("Server cookie must be between 8 and 32 bytes.", nameof(serverCookie));
            }

            _clientCookie = clientCookie;
            _serverCookie = serverCookie;
        }

        public EDnsCookieOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static EDnsOption[] GetEDnsCookieOption(byte[] clientCookie, byte[] serverCookie = null)
        {
            return new EDnsOption[] { new EDnsOption(EDnsOptionCode.COOKIE, new EDnsCookieOptionData(clientCookie, serverCookie)) };
        }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            if (_length < 8)
                throw new InvalidDataException("DNS Cookie option data must be at least 8 bytes.");

            if (_length > 40)
                throw new InvalidDataException("DNS Cookie option data must not exceed 40 bytes.");

            _clientCookie = s.ReadExactly(8);

            int serverCookieLength = _length - 8;
            if (serverCookieLength > 0)
            {
                if (serverCookieLength < 8 || serverCookieLength > 32)
                    throw new InvalidDataException("Server cookie must be between 8 and 32 bytes.");

                _serverCookie = s.ReadExactly(serverCookieLength);
            }
        }

        protected override void WriteOptionData(Stream s)
        {
            s.Write(_clientCookie);

            if (_serverCookie is not null)
                s.Write(_serverCookie);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsCookieOptionData other)
            {
                if (!_clientCookie.SequenceEqual(other._clientCookie))
                    return false;

                if (_serverCookie is null && other._serverCookie is null)
                    return true;

                if (_serverCookie is null || other._serverCookie is null)
                    return false;

                return _serverCookie.SequenceEqual(other._serverCookie);
            }

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();

            hash.AddBytes(_clientCookie);

            if (_serverCookie is not null)
                hash.AddBytes(_serverCookie);

            return hash.ToHashCode();
        }

        public override string ToString()
        {
            string clientCookieHex = Convert.ToHexString(_clientCookie);
            
            if (_serverCookie is null)
                return "[Client Cookie: " + clientCookieHex + "]";

            string serverCookieHex = Convert.ToHexString(_serverCookie);
            return "[Client Cookie: " + clientCookieHex + ", Server Cookie: " + serverCookieHex + "]";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("ClientCookie", Convert.ToHexString(_clientCookie));

            if (_serverCookie is not null)
                jsonWriter.WriteString("ServerCookie", Convert.ToHexString(_serverCookie));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public byte[] ClientCookie
        { get { return _clientCookie; } }

        public byte[] ServerCookie
        { get { return _serverCookie; } }

        public override int UncompressedLength
        { get { return 8 + (_serverCookie is null ? 0 : _serverCookie.Length); } }

        #endregion
    }
}
