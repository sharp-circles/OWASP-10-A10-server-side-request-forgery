# OWASP-10-A10-server-side-request-forgery

Port scanning and sensitive file data exposure over a web .NET application

This repository demonstrates the mechanics of **Server-Side Request Forgery (SSRF)** within a .NET environment. It covers how internal resources can be exposed via port scanning and how to implement robust application-layer defenses.

## 📌 Overview

SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL. An attacker can coerce the application to send requests to internal-only destinations, bypassing firewalls and ACLs.

### The threat

* **Internal scanning:** Mapping the internal network from an external-facing web server.
* **Cloud metadata access:** Stealing credentials from cloud instance metadata services (e.g., IMDSv2).
* **Data exfiltration:** Accessing internal-only APIs or sensitive local files.

---

## 🔍 Scenario 1: Internal port scanning with nmap

In a typical SSRF attack, an attacker might use the server as a proxy to scan the internal network. We simulate the "visibility" an attacker gains by using **Nmap** to probe a local environment.

### Basic scan

To identify open ports and services on the host:

```bash
nmap -v -A -p 5000-8000 localhost

```

### Analysis of results

From the scan output, we can extract high-value intelligence:

* **Web Server:** Microsoft Kestrel (identifies the .NET stack).
* **Operating System:** Windows 10 (versions 1809 - 21H2).
* **Internal Services:** * `5127/tcp`: HTTP (Kestrel)
* `7175/tcp`: HTTPS (Kestrel) with SSL certificate details.
* `5357/tcp`: Microsoft HTTPAPI 2.0.

### Evasion techniques

Nmap provides tools for testing how well protected a system is against discovery:

```bash
# Spoof source address
nmap -S <IP_Address> <Target>

# Relay connections through proxies
nmap --proxies <url1,url2> <Target>

```

---

## 💻 Scenario 2: Vulnerable .NET implementation

The following code represents a classic SSRF vulnerability where a `proxyUrl` is accepted from a user and requested by the server without validation.

```csharp
[HttpGet(Name = "GetExternalWeather")]
public async Task<IActionResult> GetExternalWeather(string proxyUrl)
{
    // VULNERABLE: No validation on the destination URL
    var client = new HttpClient();
    var response = await client.GetStringAsync(proxyUrl);

    return Ok(response);
}

```

**Attack vector:**
A user could supply: `?proxyUrl=http://localhost:5000/internal-admin-panel` to access restricted areas.

---

## 🛡️ Mitigation & Prevention

### 1. Network layer (Defense in depth)

* **Segmentation:** Isolate the application in a DMZ.
* **Deny-by-Default:** Block all outgoing traffic except to known, required endpoints.
* **Logging:** Monitor all outbound requests originating from the application server.

### 2. Application layer (Secure coding)

Implement a `SocketsHttpHandler` to intercept and validate requests at the DNS/IP level before they leave the server. This prevents attackers from using DNS rebinding to bypass simple string-based allow lists.

```csharp
public HttpClient CreateSecureHttpClient()
{
    var handler = new SocketsHttpHandler
    {
        ConnectCallback = async (context, cancellationToken) =>
        {
            var address = context.DnsEndPoint.Host;
            var port = context.DnsEndPoint.Port;

            // Resolve the hostname to IP addresses
            var entry = await Dns.GetHostEntryAsync(address, cancellationToken);

            foreach (var ip in entry.AddressList)
            {
                // Check if the IP belongs to a forbidden or private range
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

    return new HttpClient(handler);
}

```

---

## 🚀 Key takeaways

1. **Always use allow lists:** Only permit requests to validated, trusted domains.
2. **Validate at the IP level:** Don't just trust the URL string; validate the resolved IP address to prevent DNS rebinding.
3. **Disable redirections:** Attackers often use 302 redirects to bypass simple URL filters.

---

**Repository:** [sharp-circles/OWASP-10-A10-server-side-request-forgery](https://www.google.com/search?q=)
