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
    public class DefaultProxyServerConnectionManagerTests
    {
        [TestMethod]
        public async Task ConnectAsync_WithIPEndPoint_ConnectsAndSetsNoDelay()
        {
            // Arrange: simple TCP listener on loopback with ephemeral port.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var localEp = (IPEndPoint)listener.LocalEndpoint;

            var manager = new DefaultProxyServerConnectionManager();

            // Act: connect to the listener using the manager.
            Socket clientSocket = await manager.ConnectAsync(localEp);

            // Assert: the connection must be established and NoDelay enabled.
            Assert.IsNotNull(clientSocket, "ConnectAsync must return a non-null Socket.");
            Assert.IsTrue(clientSocket.Connected, "Returned Socket must be connected to the remote endpoint.");
            Assert.AreEqual(AddressFamily.InterNetwork, clientSocket.AddressFamily, "Socket AddressFamily must match the endpoint.");
            Assert.IsTrue(clientSocket.NoDelay, "ConnectAsync must set NoDelay=true on the created Socket.");

            // Assert: server side actually sees the connection.
            using Socket serverSocket = await listener.AcceptSocketAsync();
            Assert.IsTrue(serverSocket.Connected, "Listener must accept a connected Socket.");

            // Cleanup
            clientSocket.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task ConnectAsync_WithDnsEndPoint_ExplicitIPv4_ResolvesAndConnects()
        {
            // Arrange
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            var remoteDns = new DnsEndPoint("localhost", port, AddressFamily.InterNetwork);
            var manager = new DefaultProxyServerConnectionManager();

            // Act
            Socket clientSocket = await manager.ConnectAsync(remoteDns);

            // Assert
            Assert.IsNotNull(clientSocket);
            Assert.IsTrue(clientSocket.Connected);
            Assert.IsTrue(clientSocket.NoDelay);

            using Socket serverSocket = await listener.AcceptSocketAsync();
            Assert.IsTrue(serverSocket.Connected);

            clientSocket.Dispose();
            listener.Stop();
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_InterNetwork_ReturnsSucceededHandlerAndAcceptsConnection()
        {
            // Arrange
            var manager = new DefaultProxyServerConnectionManager();

            // Act
            var handler = await manager.GetBindHandlerAsync(AddressFamily.InterNetwork);

            // Assert reply code and local endpoint
            Assert.IsNotNull(handler, "GetBindHandlerAsync must return a non-null bind handler for IPv4.");
            Assert.AreEqual(SocksProxyReplyCode.Succeeded, handler.ReplyCode,
                "IPv4 BindHandler must report Succeeded when a default IPv4 network is available.");

            var bindEp = handler.ProxyLocalEndPoint as IPEndPoint;
            Assert.IsNotNull(bindEp, "ProxyLocalEndPoint must be an IPEndPoint.");
            Assert.AreEqual(AddressFamily.InterNetwork, bindEp.AddressFamily,
                "ProxyLocalEndPoint must use IPv4 address family.");
            Assert.IsTrue(bindEp.Port > 0, "Bind handler must listen on a non-zero port.");

            // Now actually accept a connection and verify ProxyRemoteEndPoint is set.
            using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            var acceptTask = handler.AcceptAsync(CancellationToken.None);
            await client.ConnectAsync(bindEp);

            using Socket accepted = await acceptTask;

            Assert.IsTrue(accepted.Connected, "AcceptAsync must return a connected Socket.");
            Assert.IsNotNull(handler.ProxyRemoteEndPoint, "ProxyRemoteEndPoint must be set after a connection is accepted.");

            var remoteEp = handler.ProxyRemoteEndPoint as IPEndPoint;
            var clientLocal = (IPEndPoint)client.LocalEndPoint;

            Assert.AreEqual(clientLocal.Address, remoteEp.Address,
                "ProxyRemoteEndPoint.Address must match the connecting client's local address.");
            Assert.AreEqual(clientLocal.Port, remoteEp.Port,
                "ProxyRemoteEndPoint.Port must match the connecting client's local port.");

            // Cleanup
            client.Dispose();
            handler.Dispose();
        }

        [TestMethod]
        public async Task GetBindHandlerAsync_UnsupportedFamily_ReturnsAddressTypeNotSupported()
        {
            // Arrange
            var manager = new DefaultProxyServerConnectionManager();

            // Act
            var handler = await manager.GetBindHandlerAsync(AddressFamily.Unspecified);

            // Assert
            Assert.IsNotNull(handler, "GetBindHandlerAsync must not return null even for unsupported family.");
            Assert.AreEqual(SocksProxyReplyCode.AddressTypeNotSupported, handler.ReplyCode,
                "Unsupported address family must set ReplyCode=AddressTypeNotSupported.");

            var bindEp = handler.ProxyLocalEndPoint as IPEndPoint;
            Assert.IsNotNull(bindEp, "ProxyLocalEndPoint must not be null even on failure.");
            Assert.AreEqual(IPAddress.Any, bindEp.Address,
                "On unsupported family, bind endpoint must be IPAddress.Any.");
            Assert.AreEqual(0, bindEp.Port,
                "On unsupported family, bind endpoint port must be 0.");

            handler.Dispose();
        }

        [TestMethod]
        public async Task BindHandler_Dispose_ThenAcceptAsync_ThrowsObjectDisposedException()
        {
            // Arrange
            var manager = new DefaultProxyServerConnectionManager();
            var handler = await manager.GetBindHandlerAsync(AddressFamily.InterNetwork);

            Assert.AreEqual(SocksProxyReplyCode.Succeeded, handler.ReplyCode,
                "Precondition: Bind handler must be in Succeeded state for this test.");

            handler.Dispose();

            // Act + Assert
            await Assert.ThrowsExactlyAsync<ObjectDisposedException>(
                () => handler.AcceptAsync(CancellationToken.None),
                "AcceptAsync must throw ObjectDisposedException after the handler is disposed.");
        }

        [TestMethod]
        public async Task GetUdpAssociateHandlerAsync_CanSendAndReceiveDatagrams()
        {
            // Arrange: pick a free UDP port on loopback to avoid port collisions.
            int udpPort = GetFreeUdpPort();
            var localBind = new IPEndPoint(IPAddress.Loopback, udpPort);

            var manager = new DefaultProxyServerConnectionManager();
            var udpHandler = await manager.GetUdpAssociateHandlerAsync(localBind);

            // remote UDP socket that will receive from the handler and send back
            using var remoteSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            remoteSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var remoteEp = (IPEndPoint)remoteSocket.LocalEndPoint;

            byte[] sendPayload = { 0x01, 0x02, 0x03, 0x04 };
            var sendSegment = new ArraySegment<byte>(sendPayload);

            // Act: handler sends to remote
            int bytesSent = await udpHandler.SendToAsync(sendSegment, remoteEp, CancellationToken.None);

            // Assert: remote receives the same bytes
            Assert.AreEqual(sendPayload.Length, bytesSent, "SendToAsync must send all bytes in the buffer.");

            var recvBuffer = new byte[256];
            EndPoint fromEp = new IPEndPoint(IPAddress.Any, 0);
            int bytesReceived = remoteSocket.ReceiveFrom(recvBuffer, ref fromEp);

            Assert.AreEqual(sendPayload.Length, bytesReceived, "Remote socket must receive exact number of bytes sent.");
            for (int i = 0; i < sendPayload.Length; i++)
            {
                Assert.AreEqual(sendPayload[i], recvBuffer[i],
                    $"Byte {i} of received datagram must match the payload.");
            }

            // Now test receive path: remote sends to handler and handler.ReceiveFromAsync must get it.
            byte[] echoPayload = { 0xAA, 0xBB, 0xCC };
            var echoSegment = new ArraySegment<byte>(echoPayload);

            // send echo to the handler's bound port (we bound handler to udpPort above).
            var handlerEp = new IPEndPoint(IPAddress.Loopback, udpPort);
            remoteSocket.SendTo(echoPayload, handlerEp);

            var recvFromBuffer = new byte[256];
            var recvFromSegment = new ArraySegment<byte>(recvFromBuffer);

            var result = await udpHandler.ReceiveFromAsync(recvFromSegment, CancellationToken.None);

            Assert.AreEqual(echoPayload.Length, result.ReceivedBytes,
                "ReceiveFromAsync must report the exact number of bytes sent to handler.");
            for (int i = 0; i < echoPayload.Length; i++)
            {
                Assert.AreEqual(echoPayload[i], recvFromBuffer[i],
                    $"Byte {i} of payload received by handler must match the echo payload.");
            }

            Assert.IsInstanceOfType(result.RemoteEndPoint, typeof(IPEndPoint),
                "ReceiveFromAsync.RemoteEndPoint must be an IPEndPoint.");
            var reportedRemote = (IPEndPoint)result.RemoteEndPoint;
            Assert.AreEqual(remoteEp.Address, reportedRemote.Address,
                "Reported remote address must match the sender's address.");

            udpHandler.Dispose();
        }

        [TestMethod]
        public async Task UdpAssociateHandler_Dispose_ThenSendToAsync_ThrowsObjectDisposedException()
        {
            // Arrange
            int udpPort = GetFreeUdpPort();
            var localBind = new IPEndPoint(IPAddress.Loopback, udpPort);

            var manager = new DefaultProxyServerConnectionManager();
            var udpHandler = await manager.GetUdpAssociateHandlerAsync(localBind);

            udpHandler.Dispose();

            byte[] buffer = { 0x10, 0x20 };
            var segment = new ArraySegment<byte>(buffer);
            var remoteEp = new IPEndPoint(IPAddress.Loopback, udpPort);

            // Act + Assert
            await Assert.ThrowsExactlyAsync<ObjectDisposedException>(
                () => udpHandler.SendToAsync(segment, remoteEp, CancellationToken.None),
                "SendToAsync must throw ObjectDisposedException after UDP handler is disposed.");
        }

        // Helper to get a free UDP port on loopback in a race-resistant way.
        private static int GetFreeUdpPort()
        {
            using var tmp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            tmp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)tmp.LocalEndPoint).Port;
        }
    }
}
