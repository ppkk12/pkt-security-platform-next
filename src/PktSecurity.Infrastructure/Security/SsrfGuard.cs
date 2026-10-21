using System.Net;
using System.Net.Sockets;

namespace PktSecurity.Infrastructure.Security;

public static class SsrfGuard
{
    public static bool IsPrivateOrRestrictedIp(IPAddress ipAddress)
    {
        // Handle IPv4 mapped to IPv6
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            ipAddress = ipAddress.MapToIPv4();
        }

        // Loopback (127.0.0.0/8 or ::1)
        if (IPAddress.IsLoopback(ipAddress))
            return true;

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ipAddress.GetAddressBytes();
            byte b0 = bytes[0];
            byte b1 = bytes[1];

            // 0.0.0.0/8 (Current network)
            if (b0 == 0) return true;

            // 10.0.0.0/8 (Private RFC 1918)
            if (b0 == 10) return true;

            // 100.64.0.0/10 (Carrier-Grade NAT)
            if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true;

            // 127.0.0.0/8 (Loopback)
            if (b0 == 127) return true;

            // 169.254.0.0/16 (Link-local & Cloud metadata e.g. 169.254.169.254)
            if (b0 == 169 && b1 == 254) return true;

            // 172.16.0.0/12 (Private RFC 1918)
            if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;

            // 192.0.0.0/24 (IETF Protocol Assignments)
            if (b0 == 192 && b1 == 0 && bytes[2] == 0) return true;

            // 192.0.2.0/24 (TEST-NET-1)
            if (b0 == 192 && b1 == 0 && bytes[2] == 2) return true;

            // 192.168.0.0/16 (Private RFC 1918)
            if (b0 == 192 && b1 == 168) return true;

            // 198.18.0.0/15 (Network benchmark tests)
            if (b0 == 198 && (b1 == 18 || b1 == 19)) return true;

            // 198.51.100.0/24 (TEST-NET-2)
            if (b0 == 198 && b1 == 51 && bytes[2] == 100) return true;

            // 203.0.113.0/24 (TEST-NET-3)
            if (b0 == 203 && b1 == 0 && bytes[2] == 113) return true;

            // 224.0.0.0/4 (Multicast)
            if (b0 >= 224 && b0 <= 239) return true;

            // 240.0.0.0/4 (Reserved / Future use)
            if (b0 >= 240) return true;

            // 255.255.255.255 (Broadcast)
            if (b0 == 255 && b1 == 255 && bytes[2] == 255 && bytes[3] == 255) return true;
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipAddress.IsIPv6LinkLocal || ipAddress.IsIPv6SiteLocal || ipAddress.IsIPv6Multicast)
                return true;

            var bytes = ipAddress.GetAddressBytes();

            // ::/128 (Unspecified)
            bool allZero = true;
            for (int i = 0; i < 16; i++)
            {
                if (bytes[i] != 0) { allZero = false; break; }
            }
            if (allZero) return true;

            // fc00::/7 (Unique local address)
            if ((bytes[0] & 0xFE) == 0xFC) return true;

            // fe80::/10 (Link-local)
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) return true;
        }

        return false;
    }

    public static async Task ValidateUrlAsync(string url, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new SecurityViolationException("SSRF_InvalidUrl", "URL cannot be empty.");

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new SecurityViolationException("SSRF_InvalidUrl", $"Invalid URL format: '{url}'.");

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            throw new SecurityViolationException("SSRF_InvalidScheme", $"Prohibited scheme '{uri.Scheme}'. Only HTTP and HTTPS are permitted.");

        IPAddress[] ipAddresses;

        // Check if host is direct IP address
        if (IPAddress.TryParse(uri.DnsSafeHost, out var directIp))
        {
            ipAddresses = new[] { directIp };
        }
        else
        {
            try
            {
                ipAddresses = await Dns.GetHostAddressesAsync(uri.DnsSafeHost, cancellationToken);
            }
            catch (Exception ex)
            {
                throw new SecurityViolationException("SSRF_DnsResolutionFailed", $"Failed to resolve host '{uri.DnsSafeHost}': {ex.Message}", ex);
            }
        }

        if (ipAddresses.Length == 0)
        {
            throw new SecurityViolationException("SSRF_NoAddressesResolved", $"No IP addresses resolved for host '{uri.DnsSafeHost}'.");
        }

        foreach (var ip in ipAddresses)
        {
            if (IsPrivateOrRestrictedIp(ip))
            {
                throw new SecurityViolationException(
                    "SSRF_BlockedRestrictedIp",
                    $"Access to host '{uri.DnsSafeHost}' ({ip}) is blocked because it resolves to a restricted or private network address.");
            }
        }
    }

    public static SocketsHttpHandler CreateSafeHttpHandler()
    {
        return new SocketsHttpHandler
        {
            ConnectCallback = async (context, cancellationToken) =>
            {
                var host = context.DnsEndPoint.Host;
                var port = context.DnsEndPoint.Port;

                IPAddress[] addresses;
                if (IPAddress.TryParse(host, out var parsedIp))
                {
                    addresses = new[] { parsedIp };
                }
                else
                {
                    addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
                }

                if (addresses.Length == 0)
                {
                    throw new SocketException((int)SocketError.HostNotFound);
                }

                foreach (var ip in addresses)
                {
                    if (IsPrivateOrRestrictedIp(ip))
                    {
                        throw new SecurityViolationException(
                            "SSRF_BlockedRestrictedIp",
                            $"Connection to '{host}' ({ip}) was blocked by SSRF defense filter.");
                    }
                }

                var targetIp = addresses[0];
                var socket = new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(targetIp, port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
    }
}
