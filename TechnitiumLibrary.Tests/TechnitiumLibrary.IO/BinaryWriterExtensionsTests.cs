using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class BinaryWriterExtensionsTests
    {
        private static (BinaryWriter writer, MemoryStream stream) CreateWriter()
        {
            var ms = new MemoryStream();
            var bw = new BinaryWriter(ms);
            return (bw, ms);
        }

        private static byte[] WrittenBytes(MemoryStream ms) =>
            ms.ToArray();

        // ---------------------------------------
        // WriteLength() tests
        // ---------------------------------------

        [TestMethod]
        public void WriteLength_ShouldEncodeSingleByte_WhenLessThan128()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();

            // WHEN
            bw.WriteLength(42);

            // THEN
            CollectionAssert.AreEqual(new byte[] { 42 }, WrittenBytes(ms));
        }

        [TestMethod]
        public void WriteLength_ShouldEncodeMultiByte_BigEndianForm()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();

            // WHEN
            // length = 0x0000012C (300 decimal)
            bw.WriteLength(300);

            // THEN
            // Prefix = 0x82 (2 bytes follow)
            // Then big-endian 01 2C
            CollectionAssert.AreEqual(
                new byte[] { 0x82, 0x01, 0x2C },
                WrittenBytes(ms)
            );
        }

        // ---------------------------------------
        // WriteBuffer()
        // ---------------------------------------

        [TestMethod]
        public void WriteBuffer_ShouldPrefixLength_AndWriteBytes()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();
            var data = new byte[] { 0xAA, 0xBB, 0xCC };

            // WHEN
            bw.WriteBuffer(data);

            // THEN
            CollectionAssert.AreEqual(
                new byte[] { 0x03, 0xAA, 0xBB, 0xCC },
                WrittenBytes(ms)
            );
        }

        [TestMethod]
        public void WriteBuffer_WithOffset_ShouldWriteExpectedSegment()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();
            var data = new byte[] { 1, 2, 3, 4, 5 };

            // WHEN
            bw.WriteBuffer(data, offset: 1, count: 3);

            // THEN
            CollectionAssert.AreEqual(
                new byte[] { 0x03, 2, 3, 4 },
                WrittenBytes(ms)
            );
        }

        // ---------------------------------------
        // WriteShortString()
        // ---------------------------------------

        [TestMethod]
        public void WriteShortString_ShouldWriteUtf8EncodedWithLength()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();
            var text = "Hello";
            var utf8 = Encoding.UTF8.GetBytes(text);

            // WHEN
            bw.WriteShortString(text);

            // THEN
            var expected = new byte[] { (byte)utf8.Length }
                .Concat(utf8)
                .ToArray();

            CollectionAssert.AreEqual(expected, WrittenBytes(ms));
        }

        [TestMethod]
        public void WriteShortString_ShouldUseSpecifiedEncoding()
        {
            // GIVEN
            var (bw, ms) = CreateWriter();
            var text = "Å";
            var enc = Encoding.UTF32;
            var bytes = enc.GetBytes(text);

            // WHEN
            bw.WriteShortString(text, enc);

            // THEN
            var expected = new byte[] { (byte)bytes.Length }
                .Concat(bytes)
                .ToArray();

            CollectionAssert.AreEqual(expected, WrittenBytes(ms));
        }

        [TestMethod]
        public void WriteShortString_ShouldThrow_WhenStringTooLong()
        {
            // GIVEN
            var (bw, _) = CreateWriter();
            var input = new string('x', 256); // UTF-8 => 256 bytes

            // WHEN–THEN
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                bw.WriteShortString(input)
            );
        }

        // ---------------------------------------
        // Write(DateTime)
        // ---------------------------------------

        [TestMethod]
        public void WriteDate_ShouldEncodeMillisecondsFromUnixEpoch()
        {
            // GIVEN
            var expected = new DateTime(2024, 1, 2, 12, 00, 00, DateTimeKind.Utc);
            var millis = (long)(expected - DateTime.UnixEpoch).TotalMilliseconds;

            var bytes = BitConverter.GetBytes(millis);
            var (bw, ms) = CreateWriter();

            // WHEN
            bw.Write(expected);

            // THEN
            CollectionAssert.AreEqual(bytes, WrittenBytes(ms));
        }
    }
}
