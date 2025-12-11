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
    public class DefaultProxyServerConnectionManagerTests
    {
        public TestContext TestContext { get; set; }

        [TestMethod]
        public async Task ConnectAsync_WithLoopbackIPEndPoint_ConnectsAndSetsNoDelay()
        {
            // Arrange: start a loopback listener on an ephemeral port.
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            IPEndPoint serverEndPoint = (IPEndPoint)listener.LocalEndpoint;

            DefaultProxyServerConnectionManager manager = new DefaultProxyServerConnectionManager();

            // Act: initiate connection via the manager.
            Task<Socket> clientTask = manager.ConnectAsync(serverEndPoint, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            Socket clientSocket = await clientTask;

            // Assert: socket is connected and NoDelay is enabled.
            Assert.IsNotNull(clientSocket, "ConnectAsync must return a non-null Socket instance.");
            Assert.IsTrue(clientSocket.Connected, "Returned Socket must be in connected state.");
            Assert.IsTrue(clientSocket.NoDelay, "DefaultProxyServerConnectionManager must enable NoDelay on connected sockets.");

            IPEndPoint? remoteEp = (IPEndPoint?)clientSocket.RemoteEndPoint;
            Assert.AreEqual(serverEndPoint.Address, remoteEp.Address, "Client socket must connect to the listener's IP address.");
            Assert.AreEqual(serverEndPoint.Port, remoteEp.Port, "Client socket must connect to the listener's TCP port.");

            // Cleanup
            clientSocket.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_WithUnsupportedFamily_ReturnsAddressTypeNotSupported()
        {
            DefaultProxyServerConnectionManager manager = new DefaultProxyServerConnectionManager();

            // Use an artificial, unsupported address family value to drive the default branch.
            AddressFamily unsupportedFamily = (AddressFamily)1234;

            IProxyServerBindHandler handler = await manager.GetBindHandlerAsync(unsupportedFamily);

            Assert.IsNotNull(handler, "GetBindHandlerAsync must return a non-null handler even for unsupported address families.");
            Assert.AreEqual(
                SocksProxyReplyCode.AddressTypeNotSupported,
                handler.ReplyCode,
                "BindHandler must report AddressTypeNotSupported for unsupported address families.");

            Assert.IsNotNull(handler.ProxyLocalEndPoint, "ProxyLocalEndPoint must be non-null for unsupported address types.");

            IPEndPoint? ep = handler.ProxyLocalEndPoint as IPEndPoint;
            Assert.IsNotNull(ep, "ProxyLocalEndPoint must be an IPEndPoint instance.");
            Assert.AreEqual(IPAddress.Any, ep.Address, "For unsupported families, BindHandler must expose IPAddress.Any as local address.");
            Assert.AreEqual(0, ep.Port, "For unsupported families, BindHandler must expose port 0 as a sentinel.");

            if (handler is IDisposable disposable)
                disposable.Dispose();
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_BindsToSpecifiedEndPoint_ReceivesDatagram()
        {
            DefaultProxyServerConnectionManager manager = new DefaultProxyServerConnectionManager();

            int port = GetFreeUdpPort();
            IPEndPoint bindEp = new IPEndPoint(IPAddress.Loopback, port);

            IProxyServerUdpAssociateHandler udpHandler = await manager.GetUdpAssociateHandlerAsync(bindEp);

            Assert.IsNotNull(udpHandler, "GetUdpAssociateHandlerAsync must return a non-null UDP handler.");

            byte[] payload = { 1, 2, 3, 4, 5 };
            byte[] buffer = new byte[payload.Length];

            // Begin receive on the handler's socket.
            Task<SocketReceiveFromResult> receiveTask =
                udpHandler.ReceiveFromAsync(new ArraySegment<byte>(buffer), TestContext.CancellationToken);

            // Send from a separate UDP socket to the known bind endpoint.
            using Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            await sender.SendToAsync(new ArraySegment<byte>(payload), SocketFlags.None, bindEp, TestContext.CancellationToken);

            SocketReceiveFromResult result = await receiveTask;

            Assert.AreEqual(
                payload.Length,
                result.ReceivedBytes,
                "UDP associate handler must receive the complete datagram payload.");

            for (int i = 0; i < payload.Length; i++)
            {
                Assert.AreEqual(
                    payload[i],
                    buffer[i],
                    $"Byte at index {i} of the received payload must match the sent payload.");
            }

            if (udpHandler is IDisposable disposable)
                disposable.Dispose();
        }

        /// <summary>
        /// Obtains a free UDP port on loopback by binding to port 0 and reading the assigned port.
        /// </summary>
        private static int GetFreeUdpPort()
        {
            using Socket tmp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            tmp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)tmp.LocalEndPoint).Port;
        }
    }
}
