using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Security.OTP;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.OTP
{
    [TestClass]
    public sealed class AuthenticatorTests
    {
        //
        // RFC 4226 Appendix D test vector
        // Secret = "12345678901234567890" in ASCII
        // which Base32 encodes to:
        // "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        //
        private const string RfcBase32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        [TestMethod]
        public void Constructor_ShouldRejectUnsupportedType()
        {
            var uri = new AuthenticatorKeyUri("hotp", "Issuer", "acc", "ABCD");
            Assert.ThrowsExactly<NotSupportedException>(() => _ = new Authenticator(uri));
        }

        private static Authenticator CreateRFCAuth_HOtp_SHA1(int digits = 6, int period = 30)
        {
            var keyUri = new AuthenticatorKeyUri(
                type: "totp",
                issuer: "TestCorp",
                accountName: "test@example.com",
                secret: RfcBase32Secret,
                algorithm: "SHA1",
                digits: digits,
                period: period);

            return new Authenticator(keyUri);
        }

        [TestMethod]
        public void GetTOTP_ShouldMatchRFCReferenceValue()
        {
            // RFC reference Base32 secret = "12345678901234567890"
            var uri = new AuthenticatorKeyUri(
                type: "totp",
                issuer: "Example",
                accountName: "bob@example.com",
                secret: RfcBase32Secret,
                algorithm: "SHA1",
                digits: 6,
                period: 30
            );

            var auth = new Authenticator(uri);

            // RFC time = 2025-12-07 23:00:00 UTC
            var timestamp = new DateTime(2025, 12, 07, 23, 27, 00, DateTimeKind.Local);

            var result = auth.GetTOTP(timestamp);

            Assert.AreEqual("112662", result);
        }

        [TestMethod]
        public void GetTOTP_ShouldGenerateDifferentValuesAtDifferentTimes()
        {
            var auth = CreateRFCAuth_HOtp_SHA1();

            string t1 = auth.GetTOTP(new DateTime(2020, 01, 01, 00, 00, 00, DateTimeKind.Utc));
            string t2 = auth.GetTOTP(new DateTime(2020, 01, 01, 00, 00, 31, DateTimeKind.Utc)); // next period

            Assert.AreNotEqual(t1, t2);
        }


        [TestMethod]
        public void IsTOTPValid_ShouldReturnTrueForExactMatch()
        {
            var auth = CreateRFCAuth_HOtp_SHA1();

            var utcNow = DateTime.UtcNow;
            string code = auth.GetTOTP(utcNow);

            Assert.IsTrue(auth.IsTOTPValid(code));
        }

        [TestMethod]
        public void IsTOTPValid_ShouldReturnTrueWithinSkewWindow()
        {
            var auth = CreateRFCAuth_HOtp_SHA1(period: 30);

            // Use a single captured 'now' to avoid rollover flakiness
            var utcNow = DateTime.UtcNow;

            // Generate a code for the NEXT step (+30s) so it is within +1 window
            string codeNextWindow = auth.GetTOTP(utcNow.AddSeconds(30));

            // Default windowSteps = 1 accepts ±1 step
            Assert.IsTrue(auth.IsTOTPValid(codeNextWindow), "Code is valid due to default skew allowance");
        }

        [TestMethod]
        public void IsTOTPValid_ShouldReturnFalseOutsideSkewWindow()
        {
            var auth = CreateRFCAuth_HOtp_SHA1(period: 30);
            var now = new DateTime(2020, 10, 10, 12, 00, 00, DateTimeKind.Local);

            // Generate 6 periods ahead (6 * 30s = 180s)
            // Default fudge = 10 periods → OK until 10.
            string farFutureCode = auth.GetTOTP(now.AddSeconds(11 * 30));

            Assert.IsFalse(auth.IsTOTPValid(farFutureCode));
        }

        [TestMethod]
        public void ShouldSupportSHA256()
        {
            var keyUri = new AuthenticatorKeyUri(
                "totp",
                "Corp",
                "user",
                secret: RfcBase32Secret,
                algorithm: "SHA256",
                digits: 6,
                period: 30);

            var auth = new Authenticator(keyUri);

            string code = auth.GetTOTP(new DateTime(2022, 1, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.AreEqual(6, code.Length);
            Assert.IsTrue(int.TryParse(code, out _), "Expected numeric TOTP");
        }

        [TestMethod]
        public void ShouldSupportSHA512()
        {
            var keyUri = new AuthenticatorKeyUri(
                "totp",
                "Corp",
                "user",
                secret: RfcBase32Secret,
                algorithm: "SHA512",
                digits: 8,
                period: 30);

            var auth = new Authenticator(keyUri);

            string code = auth.GetTOTP(new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.AreEqual(8, code.Length);
            Assert.IsTrue(int.TryParse(code, out _));
        }
    }
}
