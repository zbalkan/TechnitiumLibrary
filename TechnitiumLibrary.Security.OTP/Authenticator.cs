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
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.OTP
{
    //HOTP: An HMAC-Based One-Time Password Algorithm
    //https://datatracker.ietf.org/doc/rfc4226/

    //TOTP: Time-Based One-Time Password Algorithm 
    //https://datatracker.ietf.org/doc/rfc6238/

    public class Authenticator
    {
        #region variables

        readonly byte[] _key;

        #endregion

        #region constructor


        public Authenticator(AuthenticatorKeyUri keyUri)
        {
            if (!keyUri.Type.Equals("totp", StringComparison.OrdinalIgnoreCase))
                throw new NotSupportedException($"The authenticator key URI type '{keyUri.Type}' is not supported.");

            KeyUri = keyUri;
            _key = Base32.FromBase32String(KeyUri.Secret);

            // Optional: validate digits per RFC common practice
            if (KeyUri.Digits < 6 || KeyUri.Digits > 8)
                throw new ArgumentOutOfRangeException(nameof(keyUri), "Digits should be 6–8 per common TOTP deployments.");
        }

        #endregion

        #region private


        private static bool ConstantTimeEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static string HOTP(byte[] k, long c, int digits = 6, string algorithm = "SHA1")
        {
            HMAC hmac = algorithm.ToUpperInvariant() switch
            {
                "SHA1" => new HMACSHA1(k),
                "SHA256" => new HMACSHA256(k),
                "SHA512" => new HMACSHA512(k),
                _ => throw new NotSupportedException("Hash algorithm is not supported: " + algorithm),
            };

            try
            {
                Span<byte> bc = stackalloc byte[8];
                BinaryPrimitives.WriteInt64BigEndian(bc, c);

                int outLength = hmac.HashSize / 8;
                Span<byte> hs = stackalloc byte[outLength];

                if (!hmac.TryComputeHash(bc, hs, out _))
                    throw new InvalidOperationException();

                int offset = hs[hs.Length - 1] & 0xf;
                int binary =
                    (hs[offset] & 0x7f) << 24 |
                    (hs[offset + 1] & 0xff) << 16 |
                    (hs[offset + 2] & 0xff) << 8 |
                    (hs[offset + 3] & 0xff);

                // integer mod instead of Math.Pow
                int mod = 1;
                for (int i = 0; i < digits; i++) mod *= 10;

                return (binary % mod).ToString().PadLeft(digits, '0');
            }
            finally
            {
                hmac.Dispose();
            }
        }
        private static string TOTP(byte[] k, DateTime dateTime, int t0 = 0, int period = 30, int digits = 6, string algorithm = "SHA1")
        {
            long t = (long)Math.Floor(((dateTime - DateTime.UnixEpoch).TotalSeconds - t0) / period);

            return HOTP(k, t, digits, algorithm);
        }
        #endregion

        #region public

        public string GetTOTP()
        {
            return GetTOTP(DateTime.UtcNow);
        }


        public string GetTOTP(DateTime dateTime)
        {
            var utc = dateTime.Kind == DateTimeKind.Utc ? dateTime : dateTime.ToUniversalTime();
            return TOTP(_key, utc, 0, KeyUri.Period, KeyUri.Digits, KeyUri.Algorithm);
        }

        public bool IsTOTPValid(string totp, int windowSteps = 1)
        {
            DateTime utcNow = DateTime.UtcNow;
            if (ConstantTimeEquals(GetTOTP(utcNow), totp)) return true;

            int period = KeyUri.Period;
            for (int i = 1; i <= windowSteps; i++)
            {
                if (ConstantTimeEquals(GetTOTP(utcNow.AddSeconds(i * period)), totp)) return true;
                if (ConstantTimeEquals(GetTOTP(utcNow.AddSeconds(-i * period)), totp)) return true;
            }
            return false;
        }

        #endregion

        #region properties

        public AuthenticatorKeyUri KeyUri { get; }

        #endregion
    }
}
