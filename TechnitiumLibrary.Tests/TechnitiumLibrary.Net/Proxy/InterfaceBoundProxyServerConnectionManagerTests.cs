using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class InterfaceBoundProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        #region helpers

        private static TcpListener StartLoopbackListener(AddressFamily family, out IPEndPoint localEndPoint)
        {
            IPAddress addr = family switch
            {
                AddressFamily.InterNetwork => IPAddress.Loopback,
                AddressFamily.InterNetworkV6 => IPAddress.IPv6Loopback,
                _ => throw new NotSupportedException("Only IPv4 and IPv6 supported.")
            };

            var listener = new TcpListener(addr, 0);
            listener.Start();

            EndPoint? ep = listener.LocalEndpoint;
            Assert.IsNotNull(ep, "TcpListener must expose a valid LocalEndpoint after Start().");
            Assert.IsInstanceOfType<IPEndPoint>(ep, "LocalEndpoint must be an IPEndPoint.");

            localEndPoint = (IPEndPoint)ep;
            return listener;
        }

        #endregion

        #region tests

        [TestMethod]
        public void Constructor_BindAddressExposedViaProperty()
        {
            var bindAddress = IPAddress.Loopback;
            var manager = new InterfaceBoundProxyServerConnectionManager(bindAddress);

            Assert.AreEqual(
                bindAddress,
                manager.BindAddress,
                "BindAddress must return the constructor-specified IP address."
            );
        }

        [TestMethod]
        public async Task ConnectAsync_WithMatchingAddressFamily_BindsAndConnectsFromBindAddress()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEndPoint);

            var manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            Socket clientSocket = await manager.ConnectAsync(serverEndPoint, TestContext.CancellationToken);

            using Socket serverSocket = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            Assert.IsTrue(clientSocket.Connected, "Returned socket must be connected.");

            EndPoint? localEp = clientSocket.LocalEndPoint;
            EndPoint? remoteEp = clientSocket.RemoteEndPoint;

            Assert.IsNotNull(localEp);
            Assert.IsNotNull(remoteEp);
            Assert.IsInstanceOfType<IPEndPoint>(localEp);
            Assert.IsInstanceOfType<IPEndPoint>(remoteEp);

            var local = (IPEndPoint)localEp;
            var remote = (IPEndPoint)remoteEp;

            Assert.AreEqual(IPAddress.Loopback, local.Address);
            Assert.AreEqual(serverEndPoint.Address, remote.Address);
            Assert.AreEqual(serverEndPoint.Port, remote.Port);
            Assert.IsTrue(clientSocket.NoDelay);

            clientSocket.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithUnspecifiedDnsEndPoint_ThrowsNotSupported()
        {
            TcpListener listener = StartLoopbackListener(AddressFamily.InterNetwork, out IPEndPoint serverEndPoint);

            var manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            // localhost resolves to IPv4 + IPv6; requesting AddressFamily.InterNetwork forces a failure
            var dnsEp = new DnsEndPoint("localhost", serverEndPoint.Port, AddressFamily.Unspecified);

            await Assert.ThrowsExactlyAsync<NotSupportedException>(
                () => manager.ConnectAsync(dnsEp, TestContext.CancellationToken),
                "Unspecified DnsEndPoint must fail resolution when multiple address families exist."
            );

            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithMismatchedFamily_ThrowsNetworkUnreachable()
        {
            var manager = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            var v6Target = new IPEndPoint(IPAddress.IPv6Loopback, 9000);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => manager.ConnectAsync(v6Target, TestContext.CancellationToken)
            );

            Assert.AreEqual(SocketError.NetworkUnreachable, ex.SocketErrorCode);
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithMatchingFamily_ReturnsHandler()
        {
            var mgr = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            var handler = await mgr.GetBindHandlerAsync(AddressFamily.InterNetwork);

            Assert.IsNotNull(handler);
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithMismatchedFamily_Throws()
        {
            var mgr = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => mgr.GetBindHandlerAsync(AddressFamily.InterNetworkV6)
            );

            Assert.AreEqual(SocketError.NetworkUnreachable, ex.SocketErrorCode);
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_WithMatchingFamily_ReturnsHandler()
        {
            var mgr = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            var local = new IPEndPoint(IPAddress.Loopback, 0);

            var handler = await mgr.GetUdpAssociateHandlerAsync(local);

            Assert.IsNotNull(handler);
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_WithMismatchedFamily_Throws()
        {
            var mgr = new InterfaceBoundProxyServerConnectionManager(IPAddress.Loopback);
            var localV6 = new IPEndPoint(IPAddress.IPv6Loopback, 0);

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                () => mgr.GetUdpAssociateHandlerAsync(localV6)
            );

            Assert.AreEqual(SocketError.NetworkUnreachable, ex.SocketErrorCode);
        }

        #endregion
    }
}
