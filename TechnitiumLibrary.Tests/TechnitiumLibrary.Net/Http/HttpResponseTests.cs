using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Http
{
    [TestClass]
    public class HttpResponseTests
    {
        public TestContext TestContext { get; set; }

        private static MemoryStream MakeStream(string ascii)
            => new MemoryStream(Encoding.ASCII.GetBytes(ascii));

        private static async Task<string> ReadAllAsciiAsync(Stream s, CancellationToken ct)
        {
            using MemoryStream ms = new MemoryStream();
            await s.CopyToAsync(ms, 8192, ct);
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenTransferEncodingChunked_ExposesDecodedBody()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "3\r\nfoo\r\n" +
                "3\r\nbar\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpResponse resp = await HttpResponse.ReadResponseAsync(
                stream,
                TestContext.CancellationToken);

            Assert.AreEqual("HTTP/1.1", resp.Protocol);
            Assert.AreEqual(200, resp.StatusCode);

            string body = await ReadAllAsciiAsync(resp.OutputStream, TestContext.CancellationToken);
            Assert.AreEqual("foobar", body);
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenTransferEncodingUnsupported_ThrowsHttpRequestException()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: br\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenChunkedTruncated_ThrowsEndOfStreamOnBodyRead()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\r\nabc";

            using MemoryStream stream = MakeStream(raw);

            HttpResponse resp = await HttpResponse.ReadResponseAsync(
                stream,
                TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await ReadAllAsciiAsync(resp.OutputStream, TestContext.CancellationToken);
            });
        }
    }
}
