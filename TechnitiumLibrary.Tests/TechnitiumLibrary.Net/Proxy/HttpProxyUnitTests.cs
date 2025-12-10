using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class HttpProxyUnitTests
    {
        public TestContext TestContext { get; set; }

        private static Task<(TcpListener listener, int port)> StartListenerAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            return Task.FromResult((listener, port));
        }

        private static async Task<string> ReadRequestAsync(Socket socket)
        {
            byte[] buffer = new byte[2048];
            int read = await socket.ReceiveAsync(buffer, SocketFlags.None);
            return Encoding.ASCII.GetString(buffer, 0, read);
        }

        private static Task<int> RespondAsync(Socket socket, string httpResponse)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(httpResponse);
            return socket.SendAsync(bytes, SocketFlags.None);
        }

        // ------------------------------------------------------------
        // 200 OK
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When200_ReturnsConnectedSocket()
        {
            var (listener, port) = await StartListenerAsync();

            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 5555);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            string request = await ReadRequestAsync(serverSide);

            Console.WriteLine("REQUEST RAW:");
            Console.WriteLine(request);

            Assert.StartsWith("CONNECT ", request);

            Assert.Contains(
                value: request,
                substring: destination.ToString(),
                message: "CONNECT request must contain 'host:port'."
            );

            await RespondAsync(serverSide, "HTTP/1.0 200 Connection Established\r\n\r\n");

            Socket result = await connectTask;
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Connected);

            result.Dispose();
            listener.Stop();
        }


        // ------------------------------------------------------------
        // 407 Authentication Required
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When407_ThrowsAuthenticationFailed()
        {
            var (listener, port) = await StartListenerAsync();
            var creds = new NetworkCredential("alice", "secret");

            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port), creds);
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 8080);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            string request = await ReadRequestAsync(serverSide);

            // TCP may split CONNECT and Proxy-Authorization into separate packets.
            if (!request.Contains("Proxy-Authorization"))
                request += await ReadRequestAsync(serverSide);

            string expectedAuth = Convert.ToBase64String(
                Encoding.ASCII.GetBytes("alice:secret")
            );

            Assert.Contains(
                value: request,
                substring: expectedAuth,
                message: "CONNECT request must include Proxy-Authorization header."
            );

            await RespondAsync(serverSide, "HTTP/1.0 407 Proxy Authentication Required\r\n\r\n");

            await Assert.ThrowsExactlyAsync<HttpProxyAuthenticationFailedException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // 500 Internal Server Error
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When500_ThrowsHttpProxyException()
        {
            var (listener, port) = await StartListenerAsync();

            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9090);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            await ReadRequestAsync(serverSide);

            await RespondAsync(serverSide, "HTTP/1.0 500 Internal Server Error\r\n\r\n");

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Malformed response
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_WhenMalformedResponse_ThrowsHttpProxyException()
        {
            var (listener, port) = await StartListenerAsync();

            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 8081);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            await ReadRequestAsync(serverSide);

            await RespondAsync(serverSide, "NOTVALID\r\n\r\n");

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Zero-byte receive
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_WhenZeroByteResponse_ThrowsHttpProxyException()
        {
            var (listener, port) = await StartListenerAsync();

            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 6060);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            await ReadRequestAsync(serverSide);

            serverSide.Shutdown(SocketShutdown.Both);
            serverSide.Close();

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Basic auth header correctness
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_IncludesBasicAuthHeader_WhenCredentialsProvided()
        {
            var (listener, port) = await StartListenerAsync();

            var creds = new NetworkCredential("userX", "pa$$word");
            var proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port), creds);

            // Use a non-bypassed address
            var destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 7007);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            string request = await ReadRequestAsync(serverSide);

            string expected = Convert.ToBase64String(Encoding.ASCII.GetBytes("userX:pa$$word"));

            Assert.Contains(
                value: request,
                substring: expected,
                message: "CONNECT request must include Proxy-Authorization header with Base64 credentials."
            );

            await RespondAsync(serverSide, "HTTP/1.0 200 OK\r\n\r\n");

            Socket finalSocket = await connectTask;
            Assert.IsTrue(finalSocket.Connected);

            finalSocket.Dispose();
            listener.Stop();
        }
    }
}