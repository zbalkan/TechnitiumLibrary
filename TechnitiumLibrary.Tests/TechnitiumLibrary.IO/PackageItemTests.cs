using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class PackageItemTests
    {
        private static MemoryStream StreamOf(params byte[] bytes) =>
            new MemoryStream(bytes, writable: true);

        private static PackageItem CreateMinimalWritable()
        {
            var ms = StreamOf(1, 2, 3);
            return new PackageItem("file.bin", ms);
        }

        // ---------------------------------------------------------
        // CONSTRUCTION
        // ---------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldCreateItemFromStream()
        {
            using var ms = StreamOf(10, 20, 30);
            using var item = new PackageItem("abc.txt", ms);

            Assert.AreEqual("abc.txt", item.Name);
            Assert.IsFalse(item.IsAttributeSet(PackageItemAttributes.ExecuteFile));
            Assert.AreEqual(ms, item.DataStream);
        }

        [TestMethod]
        public void Constructor_FromFilePath_ShouldCaptureAttributesAndOwnStream()
        {
            // Create an isolated private subfolder under temp,
            // because direct writes to global temp root are unsafe.
            string secureTempRoot = Path.Combine(
                Path.GetTempPath(),
                "pkgtest_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(secureTempRoot);

            string path = Path.Combine(
                secureTempRoot,
                Path.GetRandomFileName());

            // Create securely using exclusive, non-shareable access
            using (var file = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None))
            {
                file.Write(new byte[] { 9, 8, 7 });
            }

            File.SetLastWriteTimeUtc(
                path,
                new DateTime(2022, 5, 1, 12, 0, 0, DateTimeKind.Utc));

            try
            {
                using var item = new PackageItem(path, PackageItemAttributes.ExecuteFile);

                Assert.AreEqual(Path.GetFileName(path), item.Name);
                Assert.IsTrue(item.IsAttributeSet(PackageItemAttributes.ExecuteFile));
                Assert.IsGreaterThanOrEqualTo(3, item.DataStream.Length);
            }
            finally
            {
                // Secure cleanup: remove file then folder
                if (File.Exists(path))
                    File.Delete(path);

                if (Directory.Exists(secureTempRoot))
                    Directory.Delete(secureTempRoot, recursive: true);
            }
        }


        // ---------------------------------------------------------
        // WRITE FORMAT + RE-PARSE
        // ---------------------------------------------------------

        private static PackageItem Roundtrip(PackageItem source)
        {
            var buffer = new MemoryStream(); // do NOT dispose here
            source.WriteTo(buffer);

            buffer.Position = 0;
            return PackageItem.Parse(buffer);
        }

        [TestMethod]
        public void WriteThenParse_ShouldReturnEquivalentName()
        {
            using var item = CreateMinimalWritable();
            using var parsed = Roundtrip(item);

            Assert.AreEqual(item.Name, parsed.Name);
        }

        [TestMethod]
        public void WriteThenParse_ShouldPreserveTimestamp()
        {
            var dt = new DateTime(2022, 10, 30, 11, 0, 0, DateTimeKind.Utc);
            using var item = new PackageItem("f", dt, StreamOf(1, 2, 3));
            using var parsed = Roundtrip(item);

            Assert.AreEqual(dt, parsed.LastModifiedUTC);
        }

        [TestMethod]
        public void WriteThenParse_ShouldPreserveAttributes()
        {
            using var item = new PackageItem("a", DateTime.UtcNow, StreamOf(1),
                attributes: PackageItemAttributes.FixedExtractLocation);

            using var parsed = Roundtrip(item);

            Assert.IsTrue(parsed.IsAttributeSet(PackageItemAttributes.FixedExtractLocation));
        }

        [TestMethod]
        public void WriteThenParse_ShouldPreserveData()
        {
            using var item = CreateMinimalWritable();
            using var parsed = Roundtrip(item);

            using var reader = new BinaryReader(parsed.DataStream);

            var bytes = reader.ReadBytes(3);

            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, bytes);
        }

        // ---------------------------------------------------------
        // CUSTOM EXTRACT LOCATION
        // ---------------------------------------------------------

        [TestMethod]
        public void WriteThenParse_WithCustomLocation_ShouldRoundtrip()
        {
            // Create a private temp subfolder so location is not globally predictable
            string secureTempRoot = Path.Combine(
                Path.GetTempPath(),
                "pkgtest_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(secureTempRoot);

            try
            {
                using var item = new PackageItem(
                    "x.txt",
                    DateTime.UtcNow,
                    StreamOf(1, 2),
                    attributes: PackageItemAttributes.FixedExtractLocation,
                    extractTo: ExtractLocation.Custom,
                    extractToCustomLocation: secureTempRoot);

                using var parsed = Roundtrip(item);

                Assert.AreEqual(secureTempRoot, parsed.ExtractToCustomLocation);
            }
            finally
            {
                if (Directory.Exists(secureTempRoot))
                    Directory.Delete(secureTempRoot, recursive: true);
            }
        }

        // ---------------------------------------------------------
        // GET EXTRACTION PATH LOGIC
        // ---------------------------------------------------------

        [TestMethod]
        public void GetExtractionFilePath_ShouldRespectFixedAttribute()
        {
            using var item = new PackageItem("abc.dll", DateTime.UtcNow,
                StreamOf(1),
                attributes: PackageItemAttributes.FixedExtractLocation,
                extractTo: ExtractLocation.System);

            var result = item.GetExtractionFilePath(ExtractLocation.Temp, null);

            // path must be under System, not requested Temp
            var expectedRoot = Package.GetExtractLocation(ExtractLocation.System, null);
            Assert.StartsWith(expectedRoot, result);
        }

        [TestMethod]
        public void GetExtractionFilePath_ShouldUseSuppliedLocation_WhenNotFixed()
        {
            using var item = new PackageItem("abc.dll", StreamOf(7));

            var path = item.GetExtractionFilePath(ExtractLocation.Temp);

            Assert.StartsWith(Path.GetTempPath(), path);
        }

        // ---------------------------------------------------------
        // EXTRACTION TRANSACTION
        // ---------------------------------------------------------

        [TestMethod]
        public void Extract_ShouldBackupExisting_WhenOverwriteEnabled()
        {
            string target = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            var originalBytes = "c"u8.ToArray();

            // Securely create target
            using (var fs = new FileStream(
                target,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None))
            {
                fs.Write(originalBytes, 0, originalBytes.Length);
            }

            string? backupPath = null;

            try
            {
                using var item = CreateMinimalWritable();
                var log = item.Extract(target, overwrite: true);

                Assert.IsNotNull(log);
                Assert.IsTrue(File.Exists(log.FilePath));

                // Track for cleanup
                backupPath = log.OriginalFilePath;

                Assert.IsTrue(File.Exists(backupPath), "Backup should exist");

                CollectionAssert.AreEqual(
                    originalBytes,
                    File.ReadAllBytes(backupPath));

                CollectionAssert.AreEqual(
                    new byte[] { 1, 2, 3 },
                    File.ReadAllBytes(target));
            }
            finally
            {
                if (File.Exists(target))
                    File.Delete(target);

                // Now valid (conditional reachability eliminated)
                if (!string.IsNullOrWhiteSpace(backupPath) && File.Exists(backupPath))
                    File.Delete(backupPath);
            }
        }

        [TestMethod]
        public void Extract_ShouldNotOverwrite_WhenFlagDisabled()
        {
            string target = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            var originalBytes = "X"u8.ToArray();

            // Create file securely
            using (var fs = new FileStream(
                target,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None))
            {
                fs.Write(originalBytes, 0, originalBytes.Length);
            }

            try
            {
                using var item = CreateMinimalWritable();
                var log = item.Extract(target, overwrite: false);

                Assert.IsNull(log, "Extract must return null when overwrite=false");
                CollectionAssert.AreEqual(originalBytes, File.ReadAllBytes(target));
            }
            finally
            {
                // cleanup
                if (File.Exists(target))
                    File.Delete(target);
            }
        }

        // ---------------------------------------------------------
        // PARSE ERROR SCENARIOS
        // ---------------------------------------------------------

        [TestMethod]
        public void Parse_ShouldThrow_WhenVersionIsUnsupported()
        {
            using var buffer = StreamOf("\t"u8.ToArray() /* invalid version */);

            Assert.ThrowsExactly<IOException>(() =>
            {
                var _ = PackageItem.Parse(buffer);
            });
        }

        [TestMethod]
        public void Parse_ShouldReturnNull_WhenEOFMarker()
        {
            using var buffer = StreamOf(0);

            var item = PackageItem.Parse(buffer);

            Assert.IsNull(item);
        }
    }
}
