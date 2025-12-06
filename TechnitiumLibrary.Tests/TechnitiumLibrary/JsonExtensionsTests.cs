using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text.Json;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    [TestClass]
    public sealed class JsonExtensionsTests
    {
        private static JsonElement ToElement(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }

        // ------------------------------
        // ARRAY READING (STRING)
        // ------------------------------

        [TestMethod]
        public void GetArray_ShouldReturnStringArray_WhenArrayExists()
        {
            // GIVEN
            var json = ToElement("""{ "values": ["a", "b", "c"] }""");

            // WHEN
            var result = json.ReadArray("values");

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual("a", result[0]);
            Assert.AreEqual("b", result[1]);
            Assert.AreEqual("c", result[2]);
        }

        [TestMethod]
        public void GetArray_ShouldReturnNull_WhenJsonContainsNull()
        {
            // GIVEN
            var json = ToElement("""{ "values": null }""");

            // WHEN
            var result = json.ReadArray("values");

            // THEN
            Assert.IsNull(result);
        }

        [TestMethod]
        public void GetArray_ShouldThrow_WhenPropertyIsNotArrayOrNull()
        {
            // GIVEN
            var json = ToElement("""{ "values": 123 }""");

            // WHEN–THEN
            Assert.ThrowsExactly<InvalidOperationException>(() => json.ReadArray("values"));
        }

        // ------------------------------
        // ARRAY READING WITH MAPPING (string→int)
        // ------------------------------

        [TestMethod]
        public void ReadArray_WithConverter_ShouldReturnMappedArray()
        {
            // GIVEN
            var json = ToElement("""{ "values": ["1","2","3"] }""");

            // WHEN
            var result = json.ReadArray("values", int.Parse);

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(1, result[0]);
            Assert.AreEqual(2, result[1]);
            Assert.AreEqual(3, result[2]);
        }

        [TestMethod]
        public void ReadArray_WithConverter_ShouldThrow_WhenConverterThrows()
        {
            // GIVEN
            var json = ToElement("""{ "values": ["bad"] }""");

            // WHEN–THEN
            Assert.ThrowsExactly<FormatException>(() =>
                json.ReadArray("values", s => int.Parse(s)));
        }

        [TestMethod]
        public void TryReadArray_WithConverter_ShouldReturnFalse_WhenPropertyMissing()
        {
            // GIVEN
            var json = ToElement("""{ "other": [1,2] }""");

            // WHEN
            var result = json.TryReadArray("values", int.Parse, out var array);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(array);
        }

        [TestMethod]
        public void TryReadArray_WithConverter_ShouldReturnTrue_WhenArrayExists()
        {
            // GIVEN
            var json = ToElement("""{ "values": ["10","20"] }""");

            // WHEN
            var result = json.TryReadArray("values", int.Parse, out var array);

            // THEN
            Assert.IsTrue(result);
            Assert.HasCount(2, array);
            Assert.AreEqual(10, array[0]);
            Assert.AreEqual(20, array[1]);
        }

        // ------------------------------
        // READ SET
        // ------------------------------

        [TestMethod]
        public void ReadArrayAsSet_ShouldReturnHashSetOfUniqueValues()
        {
            // GIVEN
            var json = ToElement("""{ "values": ["a","b","a"] }""");

            // WHEN
            var result = json.ReadArrayAsSet("values");

            // THEN
            Assert.HasCount(2, result);
            Assert.Contains("a", result);
            Assert.Contains("b", result);
        }

        [TestMethod]
        public void TryReadArrayAsSet_ShouldReturnFalse_WhenNoProperty()
        {
            // GIVEN
            var json = ToElement("""{ "other": [] }""");

            // WHEN
            var result = json.TryReadArrayAsSet("values", out var set);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(set);
        }

        // ------------------------------
        // MAP READING
        // ------------------------------

        [TestMethod]
        public void ReadArrayAsMap_ShouldReturnDictionary_WhenMappingReturnsPairs()
        {
            // GIVEN
            var json = ToElement("""{ "values": [ { "k":"x","v":"1" }, { "k":"y","v":"2"} ] }""");

            // WHEN
            var result = json.ReadArrayAsMap("values", el =>
            {
                var key = el.GetProperty("k").GetString();
                var val = int.Parse(el.GetProperty("v").GetString());
                return Tuple.Create(key, val);
            });

            // THEN
            Assert.HasCount(2, result);
            Assert.AreEqual(1, result["x"]);
            Assert.AreEqual(2, result["y"]);
        }

        [TestMethod]
        public void TryReadArrayAsMap_ShouldReturnFalse_WhenPropertyMissing()
        {
            // GIVEN
            var json = ToElement("""{ "other": [] }""");

            // WHEN
            var result = json.TryReadArrayAsMap<int,int>("values", el => null, out var map);

            // THEN
            Assert.IsFalse(result);
            Assert.IsNull(map);
        }

        // ------------------------------
        // GET PROPERTY VALUE
        // ------------------------------

        [TestMethod]
        public void GetPropertyValue_String_ShouldReturnDefault_WhenMissing()
        {
            // GIVEN
            var json = ToElement("""{ "name": "test" }""");

            // WHEN
            var value = json.GetPropertyValue("missing", "default");

            // THEN
            Assert.AreEqual("default", value);
        }

        [TestMethod]
        public void GetPropertyValue_Int_ShouldReturnStoredValue()
        {
            // GIVEN
            var json = ToElement("""{ "value": 42 }""");

            // WHEN
            var value = json.GetPropertyValue("value", -1);

            // THEN
            Assert.AreEqual(42, value);
        }

        [TestMethod]
        public void GetPropertyEnumValue_ShouldReturnEnum()
        {
            // GIVEN
            var json = ToElement("""{ "mode": "Friday" }""");

            // WHEN
            var result = json.GetPropertyEnumValue("mode", DayOfWeek.Monday);

            // THEN
            Assert.AreEqual(DayOfWeek.Friday, result);
        }

        [TestMethod]
        public void GetPropertyEnumValue_ShouldReturnDefault_WhenNotFound()
        {
            // GIVEN
            var json = ToElement("""{ "val": 10 }""");

            // WHEN
            var result = json.GetPropertyEnumValue("missing", DayOfWeek.Sunday);

            // THEN
            Assert.AreEqual(DayOfWeek.Sunday, result);
        }

        // ------------------------------
        // WRITE ARRAY
        // ------------------------------

        [TestMethod]
        public void WriteStringArray_ShouldSerializeStrings_AsJsonArray()
        {
            // GIVEN
            var input = new[] { "x", "y", "z" };
            using var buffer = new System.IO.MemoryStream();
            using var writer = new Utf8JsonWriter(buffer);

            // WHEN
            writer.WriteStartObject();
            writer.WriteStringArray("values", input);
            writer.WriteEndObject();
            writer.Flush();

            var json = JsonDocument.Parse(buffer.ToArray()).RootElement;

            // THEN
            var arr = json.GetProperty("values").EnumerateArray().Select(x => x.GetString()).ToArray();

            Assert.HasCount(3, arr);
            Assert.AreEqual("x", arr[0]);
            Assert.AreEqual("y", arr[1]);
            Assert.AreEqual("z", arr[2]);
        }
    }
}
