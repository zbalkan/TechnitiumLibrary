using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class StreamExtensionsTests
    {
        private static MemoryStream StreamOf(params byte[] data) =>
            new MemoryStream(data, writable: true);

        // --------------------------------------------------------------------
        // ReadByteValue & WriteByteAsync
        // --------------------------------------------------------------------

        [TestMethod]
        public void ReadByteValue_ShouldReturnFirstByte()
        {
            using var s = StreamOf(99);
            Assert.AreEqual(99, s.ReadByteValue());
        }

        [TestMethod]
        public void ReadByteValue_ShouldThrow_WhenEmpty()
        {
            using var s = StreamOf();
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadByteValue());
        }

        [TestMethod]
        public async Task WriteByteAsync_ShouldWriteByte()
        {
            using var s = new MemoryStream(); // expandable stream

            await s.WriteByteAsync(42);

            s.Position = 0;

            Assert.AreEqual(42, s.ReadByteValue());
        }

        // --------------------------------------------------------------------
        // ReadExactly
        // --------------------------------------------------------------------

        [TestMethod]
        public void ReadExactly_ShouldReturnRequestedBytes()
        {
            using var s = StreamOf(1, 2, 3, 4);
            var data = s.ReadExactly(3);

            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, data);
        }

        [TestMethod]
        public void ReadExactly_ShouldThrow_WhenInsufficientData()
        {
            using var s = StreamOf(1, 2);
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadExactly(3));
        }

        [TestMethod]
        public async Task ReadExactlyAsync_ShouldReturnRequestedBytes()
        {
            using var s = StreamOf(10, 20, 30);
            var result = await s.ReadExactlyAsync(2);

            CollectionAssert.AreEqual(new byte[] { 10, 20 }, result);
        }

        [TestMethod]
        public async Task ReadExactlyAsync_ShouldThrow_WhenStreamEnds()
        {
            using var s = StreamOf(5);
            await Assert.ThrowsExactlyAsync<EndOfStreamException>(() => s.ReadExactlyAsync(2));
        }

        // --------------------------------------------------------------------
        // Short string read/write
        // --------------------------------------------------------------------

        [TestMethod]
        public void WriteShortString_ThenReadShortString_ShouldRoundtrip()
        {
            using var s = new MemoryStream(); // expandable stream

            s.WriteShortString("Hello");

            s.Position = 0;
            var str = s.ReadShortString();

            Assert.AreEqual("Hello", str);
        }

        [TestMethod]
        public void WriteShortString_ShouldThrow_WhenLengthExceeds255()
        {
            string oversized = new string('A', 300);

            using var s = StreamOf();
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => s.WriteShortString(oversized));
        }

        [TestMethod]
        public void ReadShortString_ShouldThrow_WhenLengthGreaterThanAvailableData()
        {
            using var s = StreamOf(2, 65); // length=2, only 1 byte remains
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadShortString());
        }

        [TestMethod]
        public async Task WriteShortStringAsync_ShouldRoundtripWithUTF8()
        {
            using var s = new MemoryStream(); // expandable

            await s.WriteShortStringAsync("test✓");

            s.Position = 0;
            var parsed = await s.ReadShortStringAsync();

            Assert.AreEqual("test✓", parsed);
        }

        // --------------------------------------------------------------------
        // CopyTo & CopyToAsync
        // --------------------------------------------------------------------

        [TestMethod]
        public void CopyTo_ShouldCopyExactBytes()
        {
            using var src = StreamOf(1, 2, 3, 4);
            using var dst = new MemoryStream(); // must be expandable here

            src.CopyTo(dst, bufferSize: 3, length: 3);

            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, dst.ToArray());
        }

        [TestMethod]
        public void CopyTo_ShouldFailWhenEOSIsReachedPrematurely()
        {
            using var src = StreamOf(1, 2);
            using var dst = new MemoryStream(); // must allow writing

            Assert.ThrowsExactly<EndOfStreamException>(() =>
                src.CopyTo(dst, bufferSize: 4, length: 3));
        }

        [TestMethod]
        public async Task CopyToAsync_ShouldCopyExactBytes()
        {
            using var src = StreamOf(99, 98, 97);
            using var dst = new MemoryStream(); // expandable destination

            await src.CopyToAsync(dst, bufferSize: 10, length: 3);

            CollectionAssert.AreEqual(new byte[] { 99, 98, 97 }, dst.ToArray());
        }

        [TestMethod]
        public async Task CopyToAsync_ShouldFailWhenEOSReachedPrematurely()
        {
            using var src = StreamOf(9);
            using var dst = new MemoryStream(); // expandable

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
                await src.CopyToAsync(dst, bufferSize: 8, length: 2));
        }

        [TestMethod]
        public void CopyTo_ShouldReturnImmediately_WhenLengthIsZero()
        {
            using var src = StreamOf(1, 2, 3);
            using var dst = StreamOf();

            src.CopyTo(dst, bufferSize: 5, length: 0);

            Assert.IsEmpty(dst.ToArray());
        }
    }
}
