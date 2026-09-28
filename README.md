# NextDNS CLI Client

NextDNS CLI is a command-line tool that allows you to use [NextDNS](https://nextdns.io)'s DNS-over-HTTPS (DoH) service with advanced capabilities. Although the most advanced features will only work with NextDNS, this program can work as a client for any DoH provider or a mix of NextDNS + another DNS (split horizon).

This CLI is mostly aimed at routers and UNIX based systems, but it is also a great client for Windows and macOS, especially for people who prefer a fully open-source client and don't mind the lack of a GUI.

See the [wiki](https://github.com/nextdns/nextdns/wiki) for installation and usage instructions.

### Shell completion

```sh
nextdns completion bash | sudo tee /etc/bash_completion.d/nextdns
nextdns completion zsh  > "${fpath[1]}/_nextdns"
nextdns completion fish > ~/.config/fish/completions/nextdns.fish
```

## DNS-over-TLS (DoT) & Android Private DNS

NextDNS CLI supports listening for incoming DNS-over-TLS (DoT, RFC 7858) connections on TCP port 853. This enables local devices—most notably Android devices using Android's native **Private DNS** feature—to use encrypted DNS directly to your NextDNS router or gateway instance.

### Configuration Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen-tls` | *(none)* | Listen address for DNS-over-TLS (e.g., `-listen-tls :853`). Can be repeated. |
| `-tls-cert` | `""` | Path to TLS certificate chain PEM file (e.g., `/etc/letsencrypt/live/router.example.com/fullchain.pem`). |
| `-tls-key` | `""` | Path to TLS private key PEM file (e.g., `/etc/letsencrypt/live/router.example.com/privkey.pem`). |
| `-max-tls-connections` | `10` | Maximum number of concurrent active DoT connections. |
| `-tls-idle-timeout` | `60s` | Idle timeout before closing inactive DoT connections. |

#### Resource Tuning on Constrained Routers
- **`-max-tls-connections` (default `10`):** Each TLS connection maintains ~40KB of TLS I/O buffers in Go. Setting this ceiling to 10 limits peak buffer memory to ~400KB, making it safe for low-RAM router firmware (32MB–64MB). Increase on hardware with ample memory.
- **`-tls-idle-timeout` (default `60s`):** Mobile clients (such as Android) pool DoT connections to minimize connection establishment overhead. A 60-second idle timeout (per RFC 7766) balances connection pooling against server resource retention while preserving client battery life.

### Android Private DNS Setup

Android (Android 9+) includes Private DNS settings supporting two operational modes:

#### 1. Strict Mode ("Private DNS provider hostname")
In Strict Mode, the device connects to port 853 of the configured hostname and validates that the TLS certificate matches this hostname:
1. Obtain a valid certificate from a publicly trusted CA (such as Let's Encrypt / Certbot) for your domain or router hostname (e.g., `router.example.com`).
2. Point your router's local DNS or `/etc/hosts` so `router.example.com` resolves to the router's LAN IP address on your local network.
3. Configure NextDNS with:
   ```sh
   nextdns run -listen-tls :853 \
     -tls-cert /etc/letsencrypt/live/router.example.com/fullchain.pem \
     -tls-key /etc/letsencrypt/live/router.example.com/privkey.pem
   ```
4. On Android, go to **Settings > Network & internet > Private DNS**, select **Private DNS provider hostname**, and enter `router.example.com`.

#### 2. Automatic Mode (Opportunistic)
In Automatic Mode, Android probes TCP port 853 on the DHCP-assigned DNS server IP address:
- Note that public CAs (such as Let's Encrypt) cannot issue certificates for RFC 1918 private IP addresses (e.g., `192.168.1.1`).
- Because Android enforces `SSL_VERIFY_PEER` against system-trusted root CAs, opportunistic DoT against a private IP requires either an internal CA with its root installed in the device's credential store, or using Strict Mode with a public hostname.

### Router & Firewall Considerations

- **Firewall Rules:** Ensure that your router's LAN firewall accepts incoming TCP traffic on port 853 (`INPUT ACCEPT`). On standard router distributions (such as OpenWrt), LAN zone traffic is accepted by default.
- **ACME Bootstrap Fallback:** When configuring `-listen-tls` without `-tls-cert` and `-tls-key`, NextDNS checks default paths (`/etc/nextdns/fullchain.pem` and `/etc/nextdns/privkey.pem`). If these files do not yet exist, NextDNS logs a warning and starts without the DoT listener, keeping standard plaintext DNS (port 53) functional so ACME clients (Certbot, acme.sh) can resolve DNS to issue the initial certificates. Once certificates are in place, restart NextDNS to activate the DoT listener. Note that explicitly specifying non-existent `-tls-cert` or `-tls-key` paths is treated as a configuration error and will prevent startup.

