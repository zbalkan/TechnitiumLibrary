using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class JointTests
    {
        private static async Task WaitForCopyCompletion()
        {
            // The copy tasks run asynchronously and Joint.Dispose() executes
            // when either side reaches EOF. Wait slightly longer than default buffering time.
            await Task.Delay(80);
        }

        // ---------------------------------------
        // Constructor and property access
        // ---------------------------------------

        [TestMethod]
        public void Constructor_ShouldStoreStreams()
        {
            // GIVEN
            var s1 = new MemoryStream();
            var s2 = new MemoryStream();

            // WHEN
            var joint = new Joint(s1, s2);

            // THEN
            Assert.AreSame(s1, joint.Stream1);
            Assert.AreSame(s2, joint.Stream2);
        }

        // ---------------------------------------
        // Data transfer behavior
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldCopyData_FromStream1ToStream2()
        {
            // GIVEN
            var sourceData = new byte[] { 1, 2, 3, 4 };
            using var s1 = new MemoryStream(sourceData);
            using var s2 = new MemoryStream();
            using var joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            var result = s2.ToArray();
            CollectionAssert.AreEqual(sourceData, result);
        }

        [TestMethod]
        public async Task Start_ShouldCopyData_FromStream2ToStream1()
        {
            // GIVEN
            var sourceData = new byte[] { 7, 8, 9 };
            using var s1 = new MemoryStream();
            using var s2 = new MemoryStream(sourceData);
            using var joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            var result = s1.ToArray();
            CollectionAssert.AreEqual(sourceData, result);
        }

        // ---------------------------------------
        // Empty stream scenarios
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldSupportEmptyStreams()
        {
            // GIVEN
            using var s1 = new MemoryStream();
            using var s2 = new MemoryStream();
            using var joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            var buff1 = s1.ToArray();
            var buff2 = s2.ToArray();

            CollectionAssert.AreEqual(Array.Empty<byte>(), buff1);
            CollectionAssert.AreEqual(Array.Empty<byte>(), buff2);
        }

        // ---------------------------------------
        // Disposal semantics
        // ---------------------------------------

        [TestMethod]
        public async Task Dispose_ShouldCloseStreams()
        {
            // GIVEN
            var s1 = new MemoryStream(new byte[] { 10 });
            var s2 = new MemoryStream(new byte[] { 20 });
            var joint = new Joint(s1, s2);

            // WHEN
            joint.Dispose();
            await WaitForCopyCompletion();

            // THEN
            Assert.ThrowsExactly<ObjectDisposedException>(() => { var _ = s1.Length; });
            Assert.ThrowsExactly<ObjectDisposedException>(() => { var _ = s2.Length; });
        }

        [TestMethod]
        public void Dispose_ShouldBeIdempotent()
        {
            // GIVEN
            var s1 = new MemoryStream();
            var s2 = new MemoryStream();
            var joint = new Joint(s1, s2);

            // WHEN
            joint.Dispose();
            joint.Dispose();
            joint.Dispose(); // Should not throw

            // THEN
            Assert.IsTrue(true); // No exception was thrown
        }

        // ---------------------------------------
        // Disposal callback behavior
        // ---------------------------------------

        [TestMethod]
        public void Dispose_ShouldRaiseDisposingEvent()
        {
            // GIVEN
            using var s1 = new MemoryStream();
            using var s2 = new MemoryStream();
            var joint = new Joint(s1, s2);

            bool raised = false;
            joint.Disposing += (_, __) => raised = true;

            // WHEN
            joint.Dispose();

            // THEN
            Assert.IsTrue(raised);
        }

        // ---------------------------------------
        // Concurrency semantics
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldDisposeOnce_WhenBothDirectionsComplete()
        {
            // GIVEN
            using var s1 = new MemoryStream(new byte[] { 1 });
            using var s2 = new MemoryStream(new byte[] { 2 });

            using var joint = new Joint(s1, s2);

            int disposedCount = 0;
            joint.Disposing += (_, __) => disposedCount++;

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            Assert.AreEqual(1, disposedCount, "Disposing must fire only once");
        }
    }
}
