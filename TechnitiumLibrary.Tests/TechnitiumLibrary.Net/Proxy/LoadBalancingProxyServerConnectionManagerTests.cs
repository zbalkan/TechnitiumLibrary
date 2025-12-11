using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class LoadBalancingProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        #region fakes

        private sealed class FakeConnectionManager : IProxyServerConnectionManager, IDisposable
        {
            readonly AddressFamily _family;

            public string Name { get; }
            public int RequestConnectCalls { get; private set; }
            public int ConnectivityCheckCalls { get; private set; }
            public EndPoint? LastRequestRemoteEndPoint { get; private set; }
            public bool FailOnRequest { get; set; }

            Socket? _requestSocket;

            public FakeConnectionManager(string name, AddressFamily family)
            {
                Name = name;
                _family = family;
            }

            public Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                // Connectivity checks use DomainEndPoint (www.google.com, etc.).
                if (remoteEP is IPEndPoint)
                {
                    RequestConnectCalls++;
                    LastRequestRemoteEndPoint = remoteEP;

                    if (FailOnRequest)
                        throw new SocketException((int)SocketError.ConnectionRefused);

                    _requestSocket ??= new Socket(_family, SocketType.Stream, ProtocolType.Tcp);
                    return Task.FromResult(_requestSocket);
                }

                ConnectivityCheckCalls++;
                // For connectivity checks, just return a disposable, unconnected socket.
                Socket s = new Socket(_family, SocketType.Stream, ProtocolType.Tcp);
                return Task.FromResult(s);
            }

            public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
            {
                throw new NotSupportedException("Bind handler not used in fake connection manager tests.");
            }

            public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
            {
                throw new NotSupportedException("UDP handler not used in fake connection manager tests.");
            }

            public void Dispose()
            {
                try
                {
                    _requestSocket?.Dispose();
                }
                catch
                {
                    // Ignore cleanup errors for test fakes.
                }
            }
        }

        #endregion

        #region tests

        [TestMethod]
        public async Task ConnectAsync_WithIpv4Endpoint_UsesIpv4ConnectionManager()
        {
            using FakeConnectionManager ipv4Manager = new FakeConnectionManager("ipv4", AddressFamily.InterNetwork);
            using FakeConnectionManager ipv6Manager = new FakeConnectionManager("ipv6", AddressFamily.InterNetworkV6);

            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                new[] { ipv6Manager });

            IPEndPoint remote = new IPEndPoint(IPAddress.Loopback, 12345);

            Socket result = await lb.ConnectAsync(remote, TestContext.CancellationToken);

            Assert.AreEqual(
                1,
                ipv4Manager.RequestConnectCalls,
                "IPv4 endpoint must be delegated exactly once to an IPv4 connection manager.");
            Assert.AreEqual(
                0,
                ipv6Manager.RequestConnectCalls,
                "IPv6 connection manager must not be used for IPv4 endpoints.");

            Assert.IsNotNull(result, "ConnectAsync must return a non-null Socket instance.");

            result.Dispose();
        }

        [TestMethod]
        public async Task ConnectAsync_WithIpv6Endpoint_UsesIpv6ConnectionManager()
        {
            using FakeConnectionManager ipv4Manager = new FakeConnectionManager("ipv4", AddressFamily.InterNetwork);
            using FakeConnectionManager ipv6Manager = new FakeConnectionManager("ipv6", AddressFamily.InterNetworkV6);

            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                new[] { ipv4Manager },
                new[] { ipv6Manager });

            IPEndPoint remote = new IPEndPoint(IPAddress.IPv6Loopback, 23456);

            Socket result = await lb.ConnectAsync(remote, TestContext.CancellationToken);

            Assert.AreEqual(
                0,
                ipv4Manager.RequestConnectCalls,
                "IPv4 connection manager must not be used for IPv6 endpoints.");
            Assert.AreEqual(
                1,
                ipv6Manager.RequestConnectCalls,
                "IPv6 endpoint must be delegated exactly once to an IPv6 connection manager.");

            Assert.IsNotNull(result, "ConnectAsync must return a non-null Socket instance.");

            result.Dispose();
        }

        [TestMethod]
        public async Task ConnectAsync_WithNoManagersAndIpv4Endpoint_ThrowsNetworkUnreachable()
        {
            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>());

            IPEndPoint remote = new IPEndPoint(IPAddress.Loopback, 34567);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => lb.ConnectAsync(remote, TestContext.CancellationToken),
                "When no connection managers exist, ConnectAsync must fail with NetworkUnreachable for IPv4 endpoints."
            );

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "ConnectAsync must report NetworkUnreachable when no IPv4 managers are available.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithNoManagersAndUnspecifiedEndpoint_ThrowsNetworkUnreachable()
        {
            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>());

            EndPoint remote = new DomainEndPoint("example.com", 80);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => lb.ConnectAsync(remote, TestContext.CancellationToken),
                "When no managers exist, ConnectAsync must fail for AddressFamily.Unspecified endpoints."
            );

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "Unspecified endpoints must also surface NetworkUnreachable when no managers are available.");
        }

        [TestMethod]
        public async Task ConnectAsync_WithMultipleIpv4Managers_RedundancyOnlyFalse_UsesExactlyOneManagerPerRequest()
        {
            using FakeConnectionManager m1 = new FakeConnectionManager("m1", AddressFamily.InterNetwork);
            using FakeConnectionManager m2 = new FakeConnectionManager("m2", AddressFamily.InterNetwork);

            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                new[] { m1, m2 },
                Array.Empty<IProxyServerConnectionManager>(),
                redundancyOnly: false);

            IPEndPoint remote = new IPEndPoint(IPAddress.Loopback, 40000);

            Socket result = await lb.ConnectAsync(remote, TestContext.CancellationToken);

            int totalRequests = m1.RequestConnectCalls + m2.RequestConnectCalls;

            Assert.AreEqual(
                1,
                totalRequests,
                "Non-redundancy load balancing must delegate each request to exactly one backend connection manager.");

            Assert.IsNotNull(result, "ConnectAsync must return a non-null Socket instance.");

            result.Dispose();
        }

        [TestMethod]
        public async Task ConnectAsync_WithMultipleIpv4Managers_RedundancyOnlyTrue_AlwaysUsesFirstManager()
        {
            using FakeConnectionManager m1 = new FakeConnectionManager("primary", AddressFamily.InterNetwork);
            using FakeConnectionManager m2 = new FakeConnectionManager("secondary", AddressFamily.InterNetwork);

            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                new[] { m1, m2 },
                Array.Empty<IProxyServerConnectionManager>(),
                redundancyOnly: true);

            IPEndPoint remote = new IPEndPoint(IPAddress.Loopback, 41000);

            // Execute multiple requests to validate deterministic primary selection.
            for (int i = 0; i < 3; i++)
            {
                using Socket s = await lb.ConnectAsync(remote, TestContext.CancellationToken);
            }

            Assert.AreEqual(
                3,
                m1.RequestConnectCalls,
                "In redundancyOnly mode, all requests must be routed to the first working connection manager.");
            Assert.AreEqual(
                0,
                m2.RequestConnectCalls,
                "Secondary connection managers must not be used when redundancyOnly is enabled.");
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithNoManagers_ThrowsNetworkUnreachable()
        {
            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>());

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => lb.GetBindHandlerAsync(AddressFamily.InterNetwork),
                "GetBindHandlerAsync must fail when no IPv4 connection managers are available."
            );

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "Bind handler lookup must surface NetworkUnreachable when no managers exist.");
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_WithNoManagers_ThrowsNetworkUnreachable()
        {
            using LoadBalancingProxyServerConnectionManager lb = new LoadBalancingProxyServerConnectionManager(
                Array.Empty<IProxyServerConnectionManager>(),
                Array.Empty<IProxyServerConnectionManager>());

            IPEndPoint local = new IPEndPoint(IPAddress.Loopback, 0);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => lb.GetUdpAssociateHandlerAsync(local),
                "GetUdpAssociateHandlerAsync must fail when no IPv4 connection managers are available."
            );

            Assert.AreEqual(
                SocketError.NetworkUnreachable,
                ex.SocketErrorCode,
                "UDP associate handler lookup must surface NetworkUnreachable when no managers exist.");
        }

        #endregion
    }
}
