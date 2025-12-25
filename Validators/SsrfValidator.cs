using System.Net.Sockets;
using System.Net;

namespace OWASP_10_A10_server_side_request_forgery.Validators;

public class SsrfValidator
{
    private readonly IPAddress[] forbiddenRanges =
        [
            IPAddress.Parse("127.0.0.1"),     
            IPAddress.Parse("169.254.169.254"),  
            IPAddress.Parse("0.0.0.0")          
        ];

    public HttpClient CreateSecureHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (context, cancellationToken) =>
            {
                var address = context.DnsEndPoint.Host;
                var port = context.DnsEndPoint.Port;

                var entry = await Dns.GetHostEntryAsync(address, cancellationToken);

                foreach (var ip in entry.AddressList)
                {
                    if (forbiddenRanges.Contains(ip) || IsPrivateIP(ip))
                    {
                        throw new HttpRequestException($"Access to internal IP {ip} is forbidden.");
                    }
                }

                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(entry.AddressList, port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
        };

        var secureClient = new HttpClient(handler);

        return secureClient;
    }

    bool IsPrivateIP(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168);
    }
}
