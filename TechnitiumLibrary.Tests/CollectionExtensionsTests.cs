using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace TechnitiumLibrary.Tests
{
    [TestClass]
    public sealed class CollectionExtensionsTests
    {
        // -------------------------------------------------------------
        // Shuffle
        // -------------------------------------------------------------

        [TestMethod]
        public void Shuffle_ShouldRearrangeItems_WhenListHasMultipleElements()
        {
            // GIVEN
            var input = new[] { 1, 2, 3, 4, 5 };
            var original = input.ToArray();

            // WHEN
            input.Shuffle();

            // THEN
            Assert.HasCount(original.Length, input, "Shuffle must not remove items.");
            Assert.IsTrue(input.All(original.Contains), "Shuffle must retain all original items.");
        }

        [TestMethod]
        public void Shuffle_ShouldNotChangeSingleElementList()
        {
            // GIVEN
            var input = new[] { 42 };

            // WHEN
            input.Shuffle();

            // THEN
            Assert.AreEqual(42, input[0]);
        }

        [TestMethod]
        public void Shuffle_ShouldNotThrow_WhenEmpty()
        {
            // GIVEN
            var input = new int[] { };

            // WHEN
            input.Shuffle();

            // THEN
            Assert.IsEmpty(input);
        }

        // -------------------------------------------------------------
        // Convert (IReadOnlyList)
        // -------------------------------------------------------------

        [TestMethod]
        public void Convert_List_ShouldTransformElements()
        {
            // GIVEN
            IReadOnlyList<int> input = new ReadOnlyCollection<int>(new[] { 1, 2, 3 });

            // WHEN
            var result = input.Convert(x => x * 10);

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(10, result[0]);
            Assert.AreEqual(20, result[1]);
            Assert.AreEqual(30, result[2]);
        }

        [TestMethod]
        public void Convert_List_ShouldThrow_WhenConverterIsNull()
        {
            // GIVEN
            IReadOnlyList<int> input = Array.Empty<int>();

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentNullException>(
                () => input.Convert<int, int>(null)
            );
        }

        // -------------------------------------------------------------
        // Convert (IReadOnlyCollection)
        // -------------------------------------------------------------

        [TestMethod]
        public void Convert_Collection_ShouldPreserveCount()
        {
            // GIVEN
            IReadOnlyCollection<string> input = new[] { "A", "BB", "CCC" };

            // WHEN
            var result = input.Convert(str => str.Length);

            // THEN
            Assert.HasCount(3, result);
        }

        [TestMethod]
        public void Convert_Collection_ShouldThrow_WhenConverterIsNull()
        {
            // GIVEN
            IReadOnlyCollection<int> input = new[] { 1, 2 };

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentNullException>(
                () => input.Convert<int, int>(null)
            );
        }

        // -------------------------------------------------------------
        // ListEquals
        // -------------------------------------------------------------

        [TestMethod]
        public void ListEquals_ShouldReturnTrue_WhenSequencesMatchExactly()
        {
            // GIVEN
            var a = new[] { 1, 2, 3 };
            var b = new[] { 1, 2, 3 };

            // WHEN
            var equal = a.ListEquals(b);

            // THEN
            Assert.IsTrue(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenLengthDiffers()
        {
            // GIVEN
            var a = new[] { 1, 2 };
            var b = new[] { 1, 2, 3 };

            // WHEN
            var equal = a.ListEquals(b);

            // THEN
            Assert.IsFalse(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenElementDiffers()
        {
            // GIVEN
            var a = new[] { 1, 2, 3 };
            var b = new[] { 1, 9, 3 };

            // WHEN
            var equal = a.ListEquals(b);

            // THEN
            Assert.IsFalse(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenSecondIsNull()
        {
            // GIVEN
            var a = new[] { "X" };

            // WHEN
            var equal = a.ListEquals(null);

            // THEN
            Assert.IsFalse(equal);
        }

        // -------------------------------------------------------------
        // HasSameItems
        // -------------------------------------------------------------

        [TestMethod]
        public void HasSameItems_ShouldReturnTrue_WhenSameElementsUnordered()
        {
            // GIVEN
            var a = new[] { 3, 1, 2 };
            var b = new[] { 2, 3, 1 };

            // WHEN
            var equal = a.HasSameItems(b);

            // THEN
            Assert.IsTrue(equal);
        }

        [TestMethod]
        public void HasSameItems_ShouldReturnFalse_WhenDifferentItemsPresent()
        {
            // GIVEN
            var a = new[] { 1, 2, 3 };
            var b = new[] { 1, 2, 4 };

            // WHEN
            var equal = a.HasSameItems(b);

            // THEN
            Assert.IsFalse(equal);
        }

        // -------------------------------------------------------------
        // GetArrayHashCode
        // -------------------------------------------------------------

        [TestMethod]
        public void GetArrayHashCode_ShouldReturnZero_WhenNull()
        {
            // WHEN
            var hash = CollectionExtensions.GetArrayHashCode<int>(null);

            // THEN
            Assert.AreEqual(0, hash);
        }

        [TestMethod]
        public void GetArrayHashCode_ShouldMatchRegardlessOfOrder()
        {
            // GIVEN
            var a = new[] { 10, 20, 30 };
            var b = new[] { 30, 10, 20 };

            // WHEN
            var hashA = a.GetArrayHashCode();
            var hashB = b.GetArrayHashCode();

            // THEN
            Assert.AreEqual(hashA, hashB, "XOR hash should not depend on order.");
        }
    }
}
