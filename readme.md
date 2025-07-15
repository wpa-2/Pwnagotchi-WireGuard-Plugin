# Pwnagotchi WireGuard Plugin

This plugin allows your Pwnagotchi to automatically connect to a home WireGuard VPN server. Once connected, it enables secure remote access (SSH, Web UI) and periodically synchronizes the entire `handshakes` directory to your server using `rsync` to ensure no data is lost.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Step 1: WireGuard Server Setup](#step-1-wireguard-server-setup)
3.  [Step 2: Pwnagotchi Dependency Installation](#step-2-pwnagotchi-dependency-installation)
4.  [Step 3: Pwnagotchi Plugin Installation](#step-3-pwnagotchi-plugin-installation)
5.  [Step 4: Pwnagotchi Configuration](#step-4-pwnagotchi-configuration)
6.  [Step 5: Enable Handshake Sync (Pwnagotchi -> Server)](#step-5-enable-handshake-sync-pwnagotchi---server)
7.  [Step 6: Enable Remote SSH (Your PC -> Pwnagotchi)](#step-6-enable-remote-ssh-your-pc---pwnagotchi)
8.  [Step 7: Enable Remote Web UI](#step-7-enable-remote-web-ui)
9.  [Step 8: Final Restart and Verification](#step-8-final-restart-and-verification)
10. [Troubleshooting](#troubleshooting)

---

### Prerequisites

* A Pwnagotchi device with network access for initial setup.
* A working WireGuard VPN server (like one set up with PiVPN).
* A remote machine (like your server or a desktop PC) for remote access.

---

### Step 1: WireGuard Server Setup

On your WireGuard server, you need to create a new client profile for your Pwnagotchi.

1.  **Create the Client Profile:**
    ```bash
    # If using PiVPN, run:
    pivpn add
    ```
    When prompted, give it a name like `pwnagotchi-client`.

2.  **Locate the Configuration File:**
    PiVPN will create a `.conf` file (e.g., `/home/your-user/configs/pwnagotchi-client.conf`). This file contains all the keys and endpoint information you will need for Step 4.

---

### Step 2: Pwnagotchi Dependency Installation

Log into your Pwnagotchi via SSH or direct connection and install the necessary tools. `rsync` is now required for syncing handshakes.

```bash
sudo apt-get update
sudo apt-get install wireguard-tools openresolv rsync git
```

---

### Step 3: Pwnagotchi Plugin Installation

1.  Clone the plugin repository from GitHub into your home directory.
    ```bash
    cd /home/pi/
    git clone https://github.com/wpa-2/Pwnagotchi-WireGuard-Plugin.git
    ```

2.  Move the plugin file to the Pwnagotchi's custom plugins directory.
    ```bash
    sudo mv /home/pi/pwnagotchi-wireguard-plugin/wireguard.py /usr/local/share/pwnagotchi/custom-plugins/
    ```

---

### Step 4: Pwnagotchi Configuration

1.  Open the main Pwnagotchi config file:
    ```bash
    sudo nano /etc/pwnagotchi/config.toml
    ```

2.  Add the following block to the file. Copy the values directly from the `.conf` file you located in Step 1.

    ```toml
    main.plugins.wireguard.enabled = true
    main.plugins.wireguard.private_key = "PASTE_CLIENT_PRIVATE_KEY_HERE"
    main.plugins.wireguard.address = "PASTE_CLIENT_ADDRESS_HERE"
    main.plugins.wireguard.dns = "1.1.1.1, 1.0.0.1" # Optional, but recommended
    main.plugins.wireguard.peer_public_key = "PASTE_SERVER_PUBLIC_KEY_HERE"
    main.plugins.wireguard.preshared_key = "PASTE_PRESHARED_KEY_HERE" # If you have one
    main.plugins.wireguard.peer_endpoint = "PASTE_SERVER_ENDPOINT_HERE"

    # --- Handshake Sync Configuration ---
    main.plugins.wireguard.server_user = "your-user-on-server"
    main.plugins.wireguard.handshake_dir = "/path/to/handshakes/on/server/"
    ```

---

### Step 5: Enable Handshake Sync (Pwnagotchi -> Server)

For the plugin to automatically sync handshakes with `rsync`, the Pwnagotchi's `root` user needs an SSH key that your server trusts.

1.  **On the Pwnagotchi**, generate a key for the `root` user. Press Enter at all prompts to accept the defaults.
    ```bash
    sudo ssh-keygen
    ```

2.  **On the Pwnagotchi**, display the new public key and copy the entire output.
    ```bash
    sudo cat /root/.ssh/id_rsa.pub
    ```

3.  **On your WireGuard Server**, add the Pwnagotchi's key to the `authorized_keys` file for the user you specified in `server_user`.
    ```bash
    # Replace 'your-user-on-server' with the actual username
    echo "PASTE_PWNAGOTCHI_PUBLIC_KEY_HERE" >> /home/your-user-on-server/.ssh/authorized_keys
    ```

---

### Step 6: Enable Remote SSH (Your PC -> Pwnagotchi)

To SSH into your Pwnagotchi over the VPN, your Pwnagotchi needs to trust the machine you are connecting *from*.

1.  **On your remote machine** (e.g., your server or desktop), generate a key if you don't have one.
    ```bash
    ssh-keygen
    ```

2.  **On your remote machine**, display the public key and copy it.
    ```bash
    cat ~/.ssh/id_rsa.pub
    ```

3.  **On the Pwnagotchi**, add the remote machine's key to the `pi` user's `authorized_keys` file.
    ```bash
    # Ensure the directory exists and has correct permissions
    mkdir -p /home/pi/.ssh
    
    # Add the key
    echo "PASTE_REMOTE_MACHINE_PUBLIC_KEY_HERE" >> /home/pi/.ssh/authorized_keys
    
    # Fix ownership and permissions
    sudo chown -R pi:pi /home/pi/.ssh
    chmod 700 /home/pi/.ssh
    chmod 600 /home/pi/.ssh/authorized_keys
    ```

---

### Step 7: Enable Remote Web UI

To access the Pwnagotchi Web UI from other devices on your home network, you must configure your WireGuard server to forward traffic.

1.  **On your WireGuard Server**, enable IP forwarding:
    ```bash
    # Uncomment the net.ipv4.ip_forward=1 line
    sudo nano /etc/sysctl.conf
    # Apply the change
    sudo sysctl -p
    ```

2.  **On your WireGuard Server**, add forwarding rules to the WireGuard config file (`/etc/wireguard/wg0.conf`). Replace `eth0` with your server's main LAN interface name (e.g., `enp3s0`).
    ```ini
    # Add these two lines under the [Interface] section
    PostUp = iptables -A FORWARD -i %i -o eth0 -j ACCEPT; iptables -A FORWARD -i eth0 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    PostDown = iptables -D FORWARD -i %i -o eth0 -j ACCEPT; iptables -D FORWARD -i eth0 -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    ```

3.  **On your Pwnagotchi**, add your home network to the web UI whitelist. Edit `/etc/pwnagotchi/config.toml` and add this block. Replace `192.168.1.0/24` with your actual home network range.
    ```toml
    main.ui.web.whitelist = [
      "127.0.0.1",
      "::1",
      "10.16.244.1",      # Your server's VPN IP
      "192.168.1.0/24",   # Your home LAN
    ]
    ```

---

### Step 8: Final Restart and Verification

1.  **On your WireGuard Server**, restart the service to apply the new firewall rules.
    ```bash
    sudo systemctl restart wg-quick@wg0
    ```

2.  **On your Pwnagotchi**, restart the service to load all new configurations.
    ```bash
    sudo systemctl restart pwnagotchi
    ```

3.  **Verify:**
    * From your remote machine, SSH into the Pwnagotchi using its VPN IP: `ssh pi@10.16.244.5`
    * From your desktop PC, open a browser to the Web UI: `http://10.16.244.5:8080`

---

### Troubleshooting

* **`Permission denied (publickey)`:** The SSH key setup is incorrect. Double-check that the correct public key was copied to the correct `authorized_keys` file on the correct machine, and that file/directory permissions are correct.
* **`Connection timed out`:** A network or firewall issue. Verify the WireGuard tunnel is active on both ends (`sudo wg show`). Check the server firewall rules and IP forwarding settings from Step 7.
* **`Unauthorized` on Web UI:** The `main.ui.web.whitelist` is missing or incorrect in the Pwnagotchi's `config.toml`, or the service was not restarted after the change.
