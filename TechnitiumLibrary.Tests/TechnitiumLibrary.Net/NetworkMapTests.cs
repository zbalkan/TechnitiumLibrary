using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class NetworkMapTests
    {
        [TestMethod]
        public void TryGetValue_ShouldReturnFalse_WhenMapIsEmpty()
        {
            var map = new NetworkMap<string>();

            bool ok = map.TryGetValue("10.1.2.3", out var value);

            Assert.IsFalse(ok, "Empty map must not resolve any address.");
            Assert.IsNull(value, "Value must be null when lookup fails.");
        }

        [TestMethod]
        public void TryGetValue_ShouldReturnAssignedValue_ForExactSingleHost()
        {
            var map = new NetworkMap<string>();
            map.Add("192.168.1.10/32", "local");

            Assert.IsTrue(map.TryGetValue("192.168.1.10", out var value),
                "Exact host entry must be resolved.");

            Assert.AreEqual("local", value,
                "Resolved value must match inserted value.");
        }

        [TestMethod]
        public void TryGetValue_ShouldMatchWithinRange_ForIPv4Subnet()
        {
            var map = new NetworkMap<int>();
            map.Add("10.0.0.0/24", 42);
            map.Add("10.0.1.0/24", 43);

            Assert.IsTrue(map.TryGetValue("10.0.0.255", out var v1),
                "Boundary address belongs to first range.");
            Assert.AreEqual(42, v1);

            Assert.IsTrue(map.TryGetValue("10.0.1.0", out var v2),
                "Exact lower bound of second range should match.");
            Assert.AreEqual(43, v2);

            Assert.IsTrue(map.TryGetValue("10.0.1.255", out var v3),
                "Upper bound of second range should match.");
            Assert.AreEqual(43, v3);

            Assert.IsFalse(map.TryGetValue("10.0.1.1", out _),
                "Interior values cannot match because floor and ceiling belong to different ranges.");
        }

        [TestMethod]
        public void TryGetValue_ShouldReturnFalse_WhenAddressOutsideRange()
        {
            var map = new NetworkMap<int>();
            map.Add("10.0.0.0/24", 11);

            bool ok = map.TryGetValue("10.0.1.1", out var value);

            Assert.IsFalse(ok, "Address outside stored range must not match.");
            Assert.AreEqual(default, value, "Value must reset on failure.");
        }

        [TestMethod]
        public void TryGetValue_ShouldPreferNearestMatchingRange_OnSortedInsertionOrder()
        {
            var map = new NetworkMap<string>();

            // Notice insertion bias: bigger range, then narrower override
            map.Add("192.168.0.0/16", "WIDE");
            map.Add("192.168.100.0/24", "TIGHT");

            Assert.IsTrue(map.TryGetValue("192.168.100.10", out var value),
                "Lookup must still resolve correct nearest boundary.");

            Assert.AreEqual("TIGHT", value,
                "More specific entry must apply implicitly via boundary comparison.");
        }

        [TestMethod]
        public void Remove_ShouldReturnTrue_WhenEntryExists()
        {
            var map = new NetworkMap<string>();
            map.Add("10.10.10.0/24", "x");

            bool removed = map.Remove("10.10.10.0/24");

            Assert.IsTrue(removed, "Remove must return true when both start and last entries are removed.");
        }

        [TestMethod]
        public void Remove_ShouldReturnFalse_WhenEntryDoesNotExist()
        {
            var map = new NetworkMap<int>();
            map.Add("192.168.1.0/24", 1);

            bool removed = map.Remove("192.168.2.0/24");

            Assert.IsFalse(removed, "Remove must fail if ranges never existed.");
        }

        [TestMethod]
        public void AfterRemove_ShouldNotResolve()
        {
            var map = new NetworkMap<string>();
            map.Add("10.0.0.0/8", "meta");

            Assert.IsTrue(map.TryGetValue("10.20.30.40", out _),
                "Initial resolution must work.");

            map.Remove("10.0.0.0/8");

            Assert.IsFalse(map.TryGetValue("10.20.30.40", out var now),
                "After removal no resolution must survive.");

            Assert.IsNull(now, "Value must reset on failure.");
        }

        [TestMethod]
        public void TryGetValue_ShouldResolveIPv6Range()
        {
            var map = new NetworkMap<string>();
            map.Add("2001:db8::/64", "v6");

            Assert.IsTrue(map.TryGetValue(IPAddress.Parse("2001:db8::abcd"), out var value),
                "IPv6 inside range must resolve correctly.");

            Assert.AreEqual("v6", value);
        }

        [TestMethod]
        public void TryGetValue_ShouldReturnFalse_WhenIPv4QueryAgainstIPv6Range()
        {
            var map = new NetworkMap<int>();
            map.Add("2001:db8::/64", 99);

            bool ok = map.TryGetValue("10.0.0.1", out var val);

            Assert.IsFalse(ok, "Mismatched families must not resolve.");
            Assert.AreEqual(default, val);
        }

        [TestMethod]
        public void AddingMultipleRanges_ShouldNotRequireManualSorting()
        {
            var map = new NetworkMap<string>();

            map.Add("10.0.0.0/24", "A");
            map.Add("10.0.1.0/24", "B");
            map.Add("10.0.2.0/24", "C");

            // The absence of prior TryGetValue calls guarantees lazy sorting is triggered here.
            Assert.IsTrue(map.TryGetValue("10.0.2.9", out var value),
                "Lookup must not depend on explicit sorting.");

            Assert.AreEqual("C", value);
        }

        [TestMethod]
        public void TryGetValue_ShouldReturnFalse_WhenFloorIsNull()
        {
            var map = new NetworkMap<string>();

            map.Add("100.0.0.0/8", "x");

            bool ok = map.TryGetValue(IPAddress.Parse("1.1.1.1"), out var result);

            Assert.IsFalse(ok, "When requested IP precedes first boundary, match must fail.");
            Assert.IsNull(result);
        }

        [TestMethod]
        public void TryGetValue_ShouldReturnFalse_WhenCeilingIsNull()
        {
            var map = new NetworkMap<string>();

            map.Add("10.0.0.0/8", "x");

            bool ok = map.TryGetValue(IPAddress.Parse("200.200.200.200"), out var result);

            Assert.IsFalse(ok, "When requested IP exceeds last boundary, match must fail.");
            Assert.IsNull(result);
        }

        [TestMethod]
        public void ValuesMustBeMatchedByReference_WhenBothBoundsHoldSameInstance()
        {
            var payload = new object();
            var map = new NetworkMap<object>();

            map.Add("10.20.30.0/24", payload);

            Assert.IsTrue(map.TryGetValue("10.20.30.50", out var resolved));
            Assert.AreSame(payload, resolved,
                "When value instance is identical, resolution must return exact object reference.");
        }
    }
}
