# OpenVPN Client

> Refer to [Github](https://github.com/utkuozdemir/dperson-openvpn-client) for the complete documentation

## Installation
This container routes all crawler traffic through a VPN connection to the outside world. Follow the following steps to install this connection properly:

1. Obtain a valid `.ovpn` file from your favorite VPN provider
2. Place this file in this (`/vpn`) folder together with the provider's `.crt` certificate
3. Make sure that the authentication within the `.ovpn` file is set to `auth-user-pass auth.txt`. If not, add this to the file manually.
4. Replace the `VPN_USER` and `VPN_PASSWORD` environment variables with the correct values.
5. While starting the container, docker-compose will put these credentials in the `auth.txt` file inside the container
6. Find out what AS number is associated with this VPN connection. Set this AS number in the `.env` file at `VPN_ASN`. This serves as a check if connections are routed through the VPN or not.
7. Start the VPN container together with the other parts of the pipeline by using `docker compose up --build`
