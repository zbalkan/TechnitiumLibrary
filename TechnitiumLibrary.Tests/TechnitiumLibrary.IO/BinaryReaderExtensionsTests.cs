using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class BinaryReaderExtensionsTests
    {
        private static BinaryReader ReaderOf(params byte[] bytes)
        {
            return new BinaryReader(new MemoryStream(bytes));
        }

        // -----------------------------------------------
        // ReadLength()
        // -----------------------------------------------

        [TestMethod]
        public void ReadLength_ShouldReadSingleByteLengths()
        {
            // GIVEN
            var reader = ReaderOf(0x05);

            // WHEN
            var length = reader.ReadLength();

            // THEN
            Assert.AreEqual(5, length);
            Assert.AreEqual(1, reader.BaseStream.Position);
        }

        [TestMethod]
        public void ReadLength_ShouldReadMultiByteBigEndianLengths()
        {
            // GIVEN
            // 0x82 => 2-byte length follows → value = 0x01 0x2C → 300 decimal
            var reader = ReaderOf(0x82, 0x01, 0x2C);

            // WHEN
            var length = reader.ReadLength();

            // THEN
            Assert.AreEqual(300, length);
            Assert.AreEqual(3, reader.BaseStream.Position);
        }

        [TestMethod]
        public void ReadLength_ShouldThrow_WhenLengthPrefixTooLarge()
        {
            // GIVEN
            // lower 7 bits = 0x05, meaning "next 5 bytes", exceeding allowed 4
            var reader = ReaderOf(0x85);

            // WHEN-THEN
            Assert.ThrowsExactly<IOException>(() => reader.ReadLength());
        }

        // -----------------------------------------------
        // ReadBuffer()
        // -----------------------------------------------

        [TestMethod]
        public void ReadBuffer_ShouldReturnBytes_WhenLengthPrefixed()
        {
            // GIVEN
            // length=3, then bytes 0xAA, 0xBB, 0xCC
            var reader = ReaderOf(0x03, 0xAA, 0xBB, 0xCC);

            // WHEN
            var data = reader.ReadBuffer();

            // THEN
            Assert.HasCount(3, data);
            CollectionAssert.AreEqual(new byte[] { 0xAA, 0xBB, 0xCC }, data);
        }

        // -----------------------------------------------
        // ReadShortString()
        // -----------------------------------------------

        [TestMethod]
        public void ReadShortString_ShouldDecodeUtf8StringCorrectly()
        {
            // GIVEN
            var text = "Hello";
            var encoded = Encoding.UTF8.GetBytes(text);

            var bytes = new byte[] { (byte)encoded.Length }.Concat(encoded).ToArray();
            var reader = ReaderOf(bytes);

            // WHEN
            var result = reader.ReadShortString();

            // THEN
            Assert.AreEqual(text, result);
        }

        [TestMethod]
        public void ReadShortString_ShouldUseSpecifiedEncoding()
        {
            // GIVEN
            var text = "Å";
            var encoding = Encoding.UTF32;
            var encoded = encoding.GetBytes(text);

            var bytes = new byte[] { (byte)encoded.Length }.Concat(encoded).ToArray();
            var reader = ReaderOf(bytes);

            // WHEN
            var result = reader.ReadShortString(encoding);

            // THEN
            Assert.AreEqual(text, result);
        }

        // -----------------------------------------------
        // ReadDateTime()
        // -----------------------------------------------

        [TestMethod]
        public void ReadDateTime_ShouldConvertEpochMilliseconds()
        {
            // GIVEN
            var expected = new DateTime(2024, 01, 01, 12, 00, 00, DateTimeKind.Utc);
            long millis = (long)(expected - DateTime.UnixEpoch).TotalMilliseconds;

            byte[] encoded = BitConverter.GetBytes(millis);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(encoded);

            var reader = ReaderOf(encoded.Reverse().ToArray());

            // WHEN
            var result = reader.ReadDateTime();

            // THEN
            Assert.AreEqual(expected, result);
        }

        // -----------------------------------------------
        // Invalid stream / broken data integrity
        // -----------------------------------------------

        [TestMethod]
        public void ReadShortString_ShouldThrow_WhenNotEnoughBytes()
        {
            // GIVEN
            // says length=4 but only 2 follow
            var reader = ReaderOf(0x04, 0xAA, 0xBB);

            // WHEN-THEN
            Assert.ThrowsExactly<EndOfStreamException>(() => reader.ReadShortString());
        }

        [TestMethod]
        public void ReadBuffer_ShouldThrow_WhenStreamEndsEarly()
        {
            // GIVEN
            // prefixed length=5, only 3 bytes exist
            var reader = ReaderOf(0x05, 0x10, 0x20, 0x30);

            // WHEN-THEN
            Assert.ThrowsExactly<EndOfStreamException>(() => reader.ReadBuffer());
        }
    }
}
