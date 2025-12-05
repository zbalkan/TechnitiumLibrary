using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using TechnitiumLibrary;

namespace TechnitiumLibrary.Tests
{
    [TestClass]
    public class BinaryNumberTests
    {
        [TestMethod]
        public void Constructor_ShouldStoreValue_WhenValidBytesProvided()
        {
            // GIVEN
            var data = new byte[] { 0x01, 0x02, 0xFF };

            // WHEN
            var bn = new BinaryNumber(data);

            // THEN
            CollectionAssert.AreEqual(data, bn.Value);
        }

        [TestMethod]
        public void Clone_ShouldReturnDeepCopy()
        {
            // GIVEN
            var bn = new BinaryNumber(new byte[] { 0xAA, 0xBB });

            // WHEN
            var clone = bn.Clone();

            // THEN
            Assert.AreNotSame(bn.Value, clone.Value);
            CollectionAssert.AreEqual(bn.Value, clone.Value);
        }

        [TestMethod]
        public void Parse_ShouldReturnCorrectBytes()
        {
            // GIVEN
            var hex = "aabbcc";

            // WHEN
            var bn = BinaryNumber.Parse(hex);

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0xAA, 0xBB, 0xCC }, bn.Value);
        }

        [TestMethod]
        public void GenerateRandomNumber160_ShouldReturn20ByteArray()
        {
            // GIVEN + WHEN
            var bn = BinaryNumber.GenerateRandomNumber160();

            // THEN
            Assert.AreEqual(20, bn.Value.Length, "Expected 160-bit random number");
        }

        [TestMethod]
        public void GenerateRandomNumber256_ShouldReturn32ByteArray()
        {
            // GIVEN + WHEN
            var bn = BinaryNumber.GenerateRandomNumber256();

            // THEN
            Assert.AreEqual(32, bn.Value.Length, "Expected 256-bit random number");
        }

        [TestMethod]
        public void Equals_ShouldReturnTrue_WhenValuesMatch()
        {
            // GIVEN
            var b1 = new BinaryNumber(new byte[] { 1, 2, 3 });
            var b2 = new BinaryNumber(new byte[] { 1, 2, 3 });

            // WHEN
            var result = b1.Equals(b2);

            // THEN
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void Equals_ShouldReturnFalse_WhenValuesDiffer()
        {
            // GIVEN
            var b1 = new BinaryNumber(new byte[] { 1, 2, 3 });
            var b2 = new BinaryNumber(new byte[] { 9, 9, 9 });

            // WHEN + THEN
            Assert.IsFalse(b1.Equals(b2));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnZero_WhenEqual()
        {
            // GIVEN
            var a = new BinaryNumber(new byte[] { 0x11, 0x22 });
            var b = new BinaryNumber(new byte[] { 0x11, 0x22 });

            // WHEN + THEN
            Assert.AreEqual(0, a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnPositive_WhenGreater()
        {
            // GIVEN
            var a = new BinaryNumber(new byte[] { 0xFF, 0x00 });
            var b = new BinaryNumber(new byte[] { 0x01, 0x00 });

            // WHEN + THEN
            Assert.AreEqual(1, a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnNegative_WhenLess()
        {
            // GIVEN
            var a = new BinaryNumber(new byte[] { 0x01, 0x00 });
            var b = new BinaryNumber(new byte[] { 0xFF, 0x00 });

            // WHEN + THEN
            Assert.AreEqual(-1, a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldThrow_WhenLengthsDiffer()
        {
            // GIVEN
            var a = new BinaryNumber(new byte[] { 0x01 });
            var b = new BinaryNumber(new byte[] { 0x01, 0x02 });

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentException>(() => a.CompareTo(b));
        }

        [TestMethod]
        public void BitwiseOr_ShouldReturnExpectedResult()
        {
            // GIVEN
            var b1 = new BinaryNumber(new byte[] { 0x0F, 0x00 });
            var b2 = new BinaryNumber(new byte[] { 0xF0, 0xFF });

            // WHEN
            var result = b1 | b2;

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0xFF, 0xFF }, result.Value);
        }

        [TestMethod]
        public void BitwiseAnd_ShouldReturnExpectedResult()
        {
            // GIVEN
            var b1 = new BinaryNumber(new byte[] { 0x0F, 0x55 });
            var b2 = new BinaryNumber(new byte[] { 0xF0, 0x0F });

            // WHEN
            var result = b1 & b2;

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0x00, 0x05 }, result.Value);
        }

        [TestMethod]
        public void BitwiseXor_ShouldReturnExpectedResult()
        {
            // GIVEN
            var b1 = new BinaryNumber(new byte[] { 0x0F, 0xAA });
            var b2 = new BinaryNumber(new byte[] { 0xFF, 0x55 });

            // WHEN
            var result = b1 ^ b2;

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0xF0, 0xFF }, result.Value);
        }

        [TestMethod]
        public void ShiftLeft_ShouldMoveBitsCorrectly()
        {
            // GIVEN
            var source = new BinaryNumber(new byte[] { 0b00000001, 0b00000000 });

            // WHEN
            var shifted = source << 1;

            // THEN
            CollectionAssert.AreEqual(
                new byte[] { 0b00000010, 0b00000000 },
                shifted.Value);
        }

        [TestMethod]
        public void ShiftRight_ShouldMoveBitsCorrectly()
        {
            // GIVEN
            var source = new BinaryNumber(new byte[] { 0b00000100, 0b00000000 });

            // WHEN
            var shifted = source >> 2;

            // THEN
            CollectionAssert.AreEqual(
                new byte[] { 0b00000001, 0b00000000 },
                shifted.Value);
        }

        [TestMethod]
        public void UnaryNot_ShouldFlipBits()
        {
            // GIVEN
            var value = new BinaryNumber(new byte[] { 0x00, 0xFF });

            // WHEN
            var inverted = ~value;

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0xFF, 0x00 }, inverted.Value);
        }

        [TestMethod]
        public void WriteTo_ShouldWriteWithLengthPrefix()
        {
            // GIVEN
            var data = new byte[] { 0x11, 0x22, 0x33 };
            var bn = new BinaryNumber(data);
            using MemoryStream ms = new();

            // WHEN
            bn.WriteTo(ms);

            // THEN
            var bytes = ms.ToArray();
            Assert.AreEqual(4, bytes.Length);
            Assert.AreEqual(3, bytes[0]);
            CollectionAssert.AreEqual(new byte[] { 0x11, 0x22, 0x33 }, bytes[1..]);
        }

        [TestMethod]
        public void Constructor_ShouldReadFromBinaryReader()
        {
            // GIVEN
            using MemoryStream ms = new();
            using var writer = new BinaryWriter(ms);
            writer.Write7BitEncodedInt(2);
            writer.Write(new byte[] { 0xDE, 0xAD });
            ms.Position = 0;

            // WHEN
            using var br = new BinaryReader(ms);
            var bn = new BinaryNumber(br);

            // THEN
            CollectionAssert.AreEqual(new byte[] { 0xDE, 0xAD }, bn.Value);
        }
    }
}
