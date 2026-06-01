# WireGuard VPN Web Panel

A lightweight C++ web panel for managing WireGuard VPN clients via a browser.

## Stack

- **C++23**
- **[Crow](https://crowcpp.org/)** — C++ web framework
- **SQLite3** — storing users and clients
- **OpenSSL** — password hashing (SHA-256), QR base64 encoding
- **WireGuard CLI** (`wg`, `wg-quick`) — VPN management

## Features

- Session-based auth with HttpOnly cookie tokens
- IP + session timeout validation on every request
- Create / delete WireGuard clients
- Auto-generate key pairs (`wg genkey` / `wg pubkey`)
- Client config file generation + QR code
- Live status polling every 5 seconds (online/offline per client)
- Start / Stop WireGuard interface
- Change login credentials

## Requirements

- Linux (Ubuntu/Debian recommended)
- WireGuard configured as `wg0`
- `qrencode` for QR code generation

```bash
sudo apt install wireguard qrencode libsqlite3-dev libssl-dev
```

## Build

```bash
cmake -B build && cmake --build build
```

## Run

```bash
sudo ./build/WebPanelVPNs
```

> `sudo` is required because `wg` and `systemctl` need root privileges.

## First launch

Create the first user via curl:

```bash
curl -X POST http://localhost:8080/api/setup \
  -d "username=admin&password=yourpassword"
```

Then open `http://YOUR_SERVER_IP:8080/login` in your browser.

## Project structure

```
main.cpp              — backend (routes, middleware, DB, WireGuard logic)
templates/
  login.html          — login page
  main_page.html      — main panel
CMakeLists.txt
```
