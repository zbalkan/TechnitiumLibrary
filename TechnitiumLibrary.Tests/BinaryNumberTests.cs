using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using TechnitiumLibrary;

namespace TechnitiumLibrary.Tests
{
    [TestClass]
    public class BinaryNumberTests
    {
        private static byte[] Bytes(params byte[] v) => v;

        // ---------------------------------------------------------------------
        //  Constructor tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldStoreReferenceValue()
        {
            // GIVEN
            var raw = Bytes(0xAA, 0xBB);

            // WHEN
            var bn = new BinaryNumber(raw);

            // THEN
            CollectionAssert.AreEqual(raw, bn.Value);
        }

        [TestMethod]
        public void Constructor_ShouldCreateFromBinaryReader_WhenValidLengthIsGiven()
        {
            // GIVEN
            using MemoryStream ms = new();
            using BinaryWriter bw = new(ms);
            bw.Write7BitEncodedInt(3);
            bw.Write(Bytes(0x11, 0x22, 0x33));
            ms.Position = 0;

            // WHEN
            using BinaryReader br = new(ms);
            var bn = new BinaryNumber(br);

            // THEN
            CollectionAssert.AreEqual(Bytes(0x11, 0x22, 0x33), bn.Value);
        }

        [TestMethod]
        public void Constructor_ShouldThrow_WhenStreamHasInsufficientBytes()
        {
            // GIVEN
            using MemoryStream ms = new();
            using BinaryWriter bw = new(ms);
            bw.Write7BitEncodedInt(5); // claims 5 bytes exist
            bw.Write(Bytes(0xAA));     // only 1 byte actually written
            ms.Position = 0;

            using BinaryReader br = new(ms);

            // WHEN + THEN
            Assert.ThrowsExactly<EndOfStreamException>(() => new BinaryNumber(br));
        }

        [TestMethod]
        public void Constructor_ShouldThrow_WhenStreamIsUnreadable()
        {
            // GIVEN
            var unreadableStream = new UnreadableStream();

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentException>(() =>
            {
                var reader = new BinaryReader(unreadableStream);
                _ = new BinaryNumber(reader); // will not be reached
            });
        }

        // ---------------------------------------------------------------------
        //  Clone tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void Clone_ShouldReturnNewInstanceWithSameBytes()
        {
            // GIVEN
            var bn = new BinaryNumber(Bytes(0x10, 0x20));

            // WHEN
            var clone = bn.Clone();

            // THEN
            Assert.AreNotSame(bn.Value, clone.Value);
            CollectionAssert.AreEqual(bn.Value, clone.Value);
        }

        // ---------------------------------------------------------------------
        //  Parse tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void Parse_ShouldDecodeHexString()
        {
            // GIVEN
            var hex = "A1B2C3";

            // WHEN
            var bn = BinaryNumber.Parse(hex);

            // THEN
            CollectionAssert.AreEqual(Bytes(0xA1, 0xB2, 0xC3), bn.Value);
        }

        [TestMethod]
        public void Parse_ShouldThrow_WhenStringContainsInvalidHex()
        {
            // GIVEN
            var badHex = "XYZ123";

            // WHEN + THEN
            Assert.ThrowsExactly<FormatException>(() => BinaryNumber.Parse(badHex));
        }

        [TestMethod]
        public void Parse_ShouldThrow_WhenInputIsNull()
        {
            // GIVEN
            string input = null;

            // THEN
            Assert.ThrowsExactly<ArgumentNullException>(() => BinaryNumber.Parse(input));
        }

        // ---------------------------------------------------------------------
        //  Static Equals(byte[], byte[]) tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void StaticEquals_ShouldReturnTrue_WhenBothNull()
        {
            // GIVEN
            byte[] a = null;
            byte[] b = null;

            // WHEN + THEN
            Assert.IsTrue(BinaryNumber.Equals(a, b));
        }

        [TestMethod]
        public void StaticEquals_ShouldReturnFalse_WhenOneSideIsNull()
        {
            // GIVEN
            byte[] a = Bytes(1, 2, 3);
            byte[] b = null;

            // WHEN + THEN
            Assert.IsFalse(BinaryNumber.Equals(a, b));
        }

        [TestMethod]
        public void StaticEquals_ShouldReturnFalse_WhenLengthsDiffer()
        {
            // GIVEN
            byte[] a = Bytes(1, 2);
            byte[] b = Bytes(1, 2, 3);

            // WHEN + THEN
            Assert.IsFalse(BinaryNumber.Equals(a, b));
        }

        [TestMethod]
        public void StaticEquals_ShouldReturnFalse_WhenContentDiffers()
        {
            // GIVEN
            byte[] a = Bytes(1, 2, 3);
            byte[] b = Bytes(1, 9, 3);

            // WHEN + THEN
            Assert.IsFalse(BinaryNumber.Equals(a, b));
        }

        // ---------------------------------------------------------------------
        //  IEquatable tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void Equals_ShouldReturnFalse_WhenOtherIsNull()
        {
            // GIVEN
            var bn = new BinaryNumber(Bytes(1, 2));

            // WHEN + THEN
            Assert.IsFalse(bn.Equals(null));
        }

        [TestMethod]
        public void EqualsObject_ShouldReturnFalse_ForIncorrectType()
        {
            // GIVEN
            var bn = new BinaryNumber(Bytes(1));

            // WHEN + THEN
            Assert.IsFalse(bn.Equals(new object()));
        }

        [TestMethod]
        public void Equals_ShouldReturnTrue_ForIdenticalValues()
        {
            var a = new BinaryNumber(Bytes(0xAA, 0xBB));
            var b = new BinaryNumber(Bytes(0xAA, 0xBB));

            Assert.IsTrue(a.Equals(b));
        }

        // ---------------------------------------------------------------------
        //  CompareTo tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void CompareTo_ShouldThrow_WhenLengthsDiffer()
        {
            // GIVEN
            var a = new BinaryNumber(Bytes(0x01));
            var b = new BinaryNumber(Bytes(0x02, 0x03));

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentException>(() => a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnZero_WhenValuesMatch()
        {
            var a = new BinaryNumber(Bytes(1, 2));
            var b = new BinaryNumber(Bytes(1, 2));

            Assert.AreEqual(0, a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnPositive_WhenAIsGreater()
        {
            var a = new BinaryNumber(Bytes(0xFF));
            var b = new BinaryNumber(Bytes(0x00));

            Assert.AreEqual(1, a.CompareTo(b));
        }

        [TestMethod]
        public void CompareTo_ShouldReturnNegative_WhenAIsSmaller()
        {
            var a = new BinaryNumber(Bytes(0x00));
            var b = new BinaryNumber(Bytes(0xFF));

            Assert.AreEqual(-1, a.CompareTo(b));
        }

        // ---------------------------------------------------------------------
        //  Operator tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void OperatorEquality_ShouldBeTrue_ForSameReference()
        {
            var bn = new BinaryNumber(Bytes(1, 2));
            Assert.IsTrue(bn == bn);
        }

        [TestMethod]
        public void OperatorInequality_ShouldBeTrue_WhenValuesDiffer()
        {
            var a = new BinaryNumber(Bytes(1, 2));
            var b = new BinaryNumber(Bytes(9, 9));
            Assert.IsTrue(a != b);
        }

        [TestMethod]
        public void OperatorOr_ShouldThrow_WhenLengthsDiffer()
        {
            var a = new BinaryNumber(Bytes(1));
            var b = new BinaryNumber(Bytes(1, 2));

            Assert.ThrowsExactly<ArgumentException>(() => _ = a | b);
        }

        [TestMethod]
        public void OperatorOr_ShouldReturnCorrectValue()
        {
            var a = new BinaryNumber(Bytes(0b00001111));
            var b = new BinaryNumber(Bytes(0b11110000));

            var result = a | b;

            CollectionAssert.AreEqual(Bytes(0b11111111), result.Value);
        }

        [TestMethod]
        public void OperatorAnd_ShouldReturnCorrectValue()
        {
            var a = new BinaryNumber(Bytes(0x0F));
            var b = new BinaryNumber(Bytes(0xF0));

            var result = a & b;

            CollectionAssert.AreEqual(Bytes(0x00), result.Value);
        }

        [TestMethod]
        public void OperatorXor_ShouldReturnCorrectValue()
        {
            var a = new BinaryNumber(Bytes(0xAA));
            var b = new BinaryNumber(Bytes(0xFF));

            var result = a ^ b;

            CollectionAssert.AreEqual(Bytes(0x55), result.Value);
        }

        [TestMethod]
        public void OperatorShiftLeft_ShouldShiftBits()
        {
            var src = new BinaryNumber(Bytes(0b00000001, 0b00000000));
            var shifted = src << 1;

            CollectionAssert.AreEqual(Bytes(0b00000010, 0b00000000), shifted.Value);
        }

        [TestMethod]
        public void OperatorShiftRight_ShouldShiftBits()
        {
            var src = new BinaryNumber(Bytes(0b00000100, 0b00000000));
            var shifted = src >> 2;

            CollectionAssert.AreEqual(Bytes(0b00000001, 0b00000000), shifted.Value);
        }

        [TestMethod]
        public void OperatorNot_ShouldInvertBits()
        {
            var src = new BinaryNumber(Bytes(0x00, 0xFF));
            var inv = ~src;

            CollectionAssert.AreEqual(Bytes(0xFF, 0x00), inv.Value);
        }

        [TestMethod]
        public void ComparisonOperators_ShouldHonorLexicographicOrder()
        {
            var a = new BinaryNumber(Bytes(1, 2));
            var b = new BinaryNumber(Bytes(9, 9));

            Assert.IsTrue(a < b);
            Assert.IsTrue(b > a);
            Assert.IsTrue(a <= b);
            Assert.IsTrue(b >= a);
        }

        [TestMethod]
        public void ComparisonOperators_ShouldThrow_WhenLengthsDiffer()
        {
            var a = new BinaryNumber(Bytes(1));
            var b = new BinaryNumber(Bytes(1, 2));

            Assert.ThrowsExactly<ArgumentException>(() => _ = a < b);
            Assert.ThrowsExactly<ArgumentException>(() => _ = a > b);
            Assert.ThrowsExactly<ArgumentException>(() => _ = a <= b);
            Assert.ThrowsExactly<ArgumentException>(() => _ = a >= b);
        }

        // ---------------------------------------------------------------------
        //  WriteTo tests
        // ---------------------------------------------------------------------

        [TestMethod]
        public void WriteTo_ShouldWritePrefixAndBytes()
        {
            var bn = new BinaryNumber(Bytes(0x11, 0x22));
            using MemoryStream ms = new();

            bn.WriteTo(ms);

            var result = ms.ToArray();
            Assert.AreEqual(3, result.Length);
            Assert.AreEqual(2, result[0]); // length prefix
            CollectionAssert.AreEqual(Bytes(0x11, 0x22), result[1..]);
        }

        // ---------------------------------------------------------------------
        //  Supporting Test Doubles
        // ---------------------------------------------------------------------

        private class UnreadableStream : Stream
        {
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => throw new IOException("Unreadable");
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}
