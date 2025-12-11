using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class NetProxyTests
    {
        public TestContext TestContext { get; set; }

        #region helpers

        private static TcpListener StartListener(IPAddress address, out IPEndPoint localEndPoint)
        {
            var listener = new TcpListener(address, 0);
            listener.Start();

            Assert.IsNotNull(listener.LocalEndpoint, "Listener.LocalEndpoint must be initialized after Start().");
            Assert.IsInstanceOfType(listener.LocalEndpoint, typeof(IPEndPoint), "Listener.LocalEndpoint must be an IPEndPoint.");

            localEndPoint = (IPEndPoint)listener.LocalEndpoint!;
            return listener;
        }

        private sealed class ChainedNetProxy : NetProxy
        {
            public ChainedNetProxy(EndPoint proxyEp)
                : base(NetProxyType.Http, proxyEp)
            {
            }

            public EndPoint? LastProxyEndPointSeen { get; private set; }
            public EndPoint? LastRemoteEndPoint { get; private set; }
            public int ProtectedConnectCallCount { get; private set; }

            protected override Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket, CancellationToken cancellationToken)
            {
                ProtectedConnectCallCount++;
                LastRemoteEndPoint = remoteEP;
                LastProxyEndPointSeen = ProxyEndPoint;
                return Task.FromResult(viaSocket);
            }
        }

        private sealed class TestNetProxy : NetProxy
        {
            public TestNetProxy(EndPoint proxyEp)
                : base(NetProxyType.Http, proxyEp)
            {
            }

            public EndPoint? LastRemoteEndPoint { get; private set; }
            public Socket? LastViaSocket { get; private set; }
            public int ProtectedConnectCallCount { get; private set; }

            protected override Task<Socket> ConnectAsync(EndPoint remoteEP, Socket viaSocket, CancellationToken cancellationToken)
            {
                ProtectedConnectCallCount++;
                LastRemoteEndPoint = remoteEP;
                LastViaSocket = viaSocket;
                return Task.FromResult(viaSocket);
            }
        }

        #endregion helpers

        #region tests

        [TestMethod]
        public void BypassList_CanBeReplacedAndAffectsIsBypassed()
        {
            var proxyEp = new IPEndPoint(IPAddress.Loopback, 8080);
            var proxy = new TestNetProxy(proxyEp);

            // Replace default bypass list with a custom one.
            proxy.BypassList = new[]
            {
                new NetProxyBypassItem("192.168.10.0/24")
            };

            var bypassed = new IPEndPoint(IPAddress.Parse("192.168.10.5"), 80);
            var notBypassed = new IPEndPoint(IPAddress.Loopback, 80); // not in our custom list

            Assert.IsTrue(proxy.IsBypassed(bypassed), "Endpoint inside configured CIDR must be treated as bypassed.");
            Assert.IsFalse(proxy.IsBypassed(notBypassed), "Endpoint outside custom bypass list must not be bypassed.");
        }

        [TestMethod]
        public async Task ConnectAsync_BypassedEndpoint_UsesDirectTcpAndSkipsProtectedConnect()
        {
            // Arrange: loopback is in the default bypass list.
            TcpListener listener = StartListener(IPAddress.Loopback, out IPEndPoint remoteEp);

            // proxyEP will never be used because remote is bypassed
            var proxyEp = new IPEndPoint(IPAddress.Loopback, 65000);
            var proxy = new TestNetProxy(proxyEp);

            // Act
            using Socket socket = await proxy.ConnectAsync(remoteEp, TestContext.CancellationToken);

            // Assert
            Assert.IsTrue(socket.Connected, "Bypassed endpoint must result in a direct TCP connection to the remote endpoint.");
            Assert.AreEqual(0, proxy.ProtectedConnectCallCount, "Protected ConnectAsync(remote, viaSocket) must not be called for bypassed endpoints.");

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_ChainOfProxies_UsesViaProxyAndThenMainProxy()
        {
            // Arrange:
            // viaProxy has its own proxy endpoint where it will open a TCP connection.
            TcpListener viaProxyListener = StartListener(IPAddress.Loopback, out IPEndPoint viaProxyEp);
            var viaProxy = new ChainedNetProxy(viaProxyEp)
            {
                // Ensure that the main proxy endpoint is NOT bypassed,
                // so viaProxy goes through its own _proxyEP instead of direct.
                BypassList = Array.Empty<NetProxyBypassItem>()
            };

            // Main proxy has its own "upstream" endpoint,
            // it will be passed as remoteEP into viaProxy.
            var mainProxyEp = new IPEndPoint(IPAddress.Loopback, 60000);
            var mainProxy = new TestNetProxy(mainProxyEp)
            {
                ViaProxy = viaProxy
            };

            // Target endpoint is non-bypassed for mainProxy (203.0.113.44 is not in default bypass list).
            var target = new IPEndPoint(IPAddress.Parse("203.0.113.44"), 443);

            // Act
            using Socket socket = await mainProxy.ConnectAsync(target, TestContext.CancellationToken);

            // Assert: viaProxy must be called once with remoteEP = mainProxy.ProxyEndPoint.
            Assert.AreEqual(1, viaProxy.ProtectedConnectCallCount, "Via proxy must have its protected ConnectAsync invoked exactly once.");
            Assert.AreEqual(mainProxyEp, viaProxy.LastRemoteEndPoint, "Via proxy must be asked to connect to the main proxy endpoint.");

            // Main proxy must then get control and see the final target.
            Assert.AreEqual(1, mainProxy.ProtectedConnectCallCount, "Main proxy must have its protected ConnectAsync invoked exactly once.");
            Assert.AreEqual(target, mainProxy.LastRemoteEndPoint, "Main proxy protected ConnectAsync must see the original target endpoint.");

            Assert.IsTrue(socket.Connected, "Final socket must be connected (it is the TCP connection created by viaProxy to its proxyEP).");

            viaProxyListener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_NonBypassedEndpoint_ConnectsToProxyEndpointAndInvokesProtectedConnect()
        {
            // Arrange: use a non-loopback address so IsBypassed returns false.
            var remote = new IPEndPoint(IPAddress.Parse("203.0.113.77"), 9000);

            // For non-bypassed endpoints, NetProxy must connect to _proxyEP.
            TcpListener proxyListener = StartListener(IPAddress.Loopback, out IPEndPoint proxyEp);

            var proxy = new TestNetProxy(proxyEp);

            // Act
            using Socket socket = await proxy.ConnectAsync(remote, TestContext.CancellationToken);

            // Assert
            Assert.AreEqual(1, proxy.ProtectedConnectCallCount, "Protected ConnectAsync must be called exactly once for non-bypassed endpoint.");
            Assert.AreEqual(remote, proxy.LastRemoteEndPoint, "Protected ConnectAsync must see the original remote endpoint.");

            Assert.IsNotNull(proxy.LastViaSocket, "Protected ConnectAsync must receive a viaSocket from GetTcpConnectionAsync.");
            Assert.AreSame(socket, proxy.LastViaSocket, "Public ConnectAsync must return exactly the viaSocket passed into protected ConnectAsync.");

            Assert.IsTrue(socket.Connected, "viaSocket returned by GetTcpConnectionAsync must be connected to the proxy endpoint.");

            proxyListener.Stop();
        }

        #endregion tests
    }
}