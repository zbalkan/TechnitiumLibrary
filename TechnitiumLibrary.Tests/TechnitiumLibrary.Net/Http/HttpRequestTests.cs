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
    public class HttpRequestTests
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
        public async Task ReadRequestAsync_WhenTransferEncodingChunked_ExposesDecodedBody()
        {
            string raw =
                "POST /submit HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "4\r\nWiki\r\n" +
                "5\r\npedia\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            Assert.AreEqual("POST", req.HttpMethod);
            Assert.AreEqual("/submit", req.RequestPath);

            string body = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            Assert.AreEqual("Wikipedia", body);
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedEndsImmediately_ReturnsEmptyBody()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            string body = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            Assert.AreEqual(string.Empty, body);
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedTruncated_ThrowsEndOfStreamOnBodyRead()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\r\nabc";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenTransferEncodingUnsupported_ThrowsHttpRequestException()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: gzip\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedBodyExceedsMaxContentLength_ThrowsHttpRequestException()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "4\r\nWiki\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                maxContentLength: 3,
                cancellationToken: TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            });
        }
    }
}
