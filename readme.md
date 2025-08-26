# Pwnagotchi WireGuard Plugin

This plugin allows your Pwnagotchi to automatically connect to a home WireGuard VPN server. Once connected, it enables secure remote access (SSH, Web UI) and periodically synchronizes handshakes and backups to your server using `rsync`.

The plugin is designed to be smart and organized. It automatically detects your Pwnagotchi's hostname and creates a dedicated folder for it on your server, keeping all files for each device neatly separated.

## Table of Contents
1.  [Prerequisites](#prerequisites)
2.  [Step 1: Server Setup](#step-1-server-setup)
3.  [Step 2: Pwnagotchi Dependency Installation](#step-2-pwnagotchi-dependency-installation)
4.  [Step 3: Plugin Installation](#step-3-plugin-installation)
5.  [Step 4: Pwnagotchi Configuration](#step-4-pwnagotchi-configuration)
6.  [Step 5: Enable Passwordless Sync (SSH Key Setup)](#step-5-enable-passwordless-sync-ssh-key-setup)
7.  [Step 6: Enable Full Remote Access (Server Firewall)](#step-6-enable-full-remote-access-server-firewall)
8.  [Step 7: Final Restart and Verification](#step-7-final-restart-and-verification)
9.  [Troubleshooting](#troubleshooting)

---

### Prerequisites

* A Pwnagotchi device with network access for the initial setup.
* A working WireGuard VPN server (e.g., set up with PiVPN).
* A server or PC on your VPN to act as the backup destination.

---

### Step 1: Server Setup

On your WireGuard server, create a new client profile for your Pwnagotchi.

1.  **Create the Client Profile:**
    ```bash
    # If using PiVPN, run:
    pivpn add
    ```
    When prompted, give it a name like `pwnagotchi-client`.

2.  **Get the Configuration:**
    PiVPN will create a `.conf` file (e.g., `/home/your-user/configs/pwnagotchi-client.conf`). You will need the keys and endpoint information from this file for Step 4.

---

### Step 2: Pwnagotchi Dependency Installation

Log into your Pwnagotchi via SSH and install `rsync`.

```bash
sudo apt-get update
sudo apt-get install rsync
```

---

### Step 3: Plugin Installation

1.  Place the `wireguard.py` script into the Pwnagotchi's custom plugins directory.
    ```bash
    # Make sure the directory exists
    sudo mkdir -p /usr/local/share/pwnagotchi/custom-plugins/
    
    # Move the plugin file (adjust the source path if needed)
    sudo mv /path/to/your/wireguard.py /usr/local/share/pwnagotchi/custom-plugins/
    ```

---

### Step 4: Pwnagotchi Configuration

1.  Open the main Pwnagotchi config file:
    ```bash
    sudo nano /etc/pwnagotchi/config.toml
    ```

2.  Add the following **required** configuration block. The only destination you need to define is `remote_base_dir`.

    ```toml
    # --- Required WireGuard Settings ---
    main.plugins.wireguard.enabled = true
    main.plugins.wireguard.private_key = "PASTE_CLIENT_PRIVATE_KEY_HERE"
    main.plugins.wireguard.address = "PASTE_CLIENT_ADDRESS_HERE"
    main.plugins.wireguard.peer_public_key = "PASTE_SERVER_PUBLIC_KEY_HERE"
    main.plugins.wireguard.peer_endpoint = "your.server.com:51820"
    main.plugins.wireguard.server_user = "your-user-on-server"
    main.plugins.wireguard.remote_base_dir = "/home/your-user/pwnagotchi_backups/"
    ```

#### Optional Configuration

You can add any of the following optional lines to the configuration block to customize the plugin's behavior.

```toml
# --- Optional Settings ---

# Add a preshared key for extra security (recommended)
main.plugins.wireguard.preshared_key = "PASTE_PRESHARED_KEY_HERE"

# Set a custom DNS server for the Pwnagotchi to use when connected
main.plugins.wireguard.dns = "9.9.9.9"

# Change the sync interval in seconds (default is 600 = 10 minutes)
main.plugins.wireguard.sync_interval_secs = 600

# --- Optional Backup Sync ---
# Set to true to also sync the backup file created by the auto-backup plugin.
# NOTE: This requires the use of the auto_backup.py plugin, available at:
# [https://github.com/wpa-2/Pwnagotchi-Plugins/blob/main/auto_backup.py](https://github.com/wpa-2/Pwnagotchi-Plugins/blob/main/auto_backup.py)
main.plugins.wireguard.sync_backup = true
```

---

### Step 5: Enable Passwordless Sync (SSH Key Setup)

For the plugin to automatically sync files, the Pwnagotchi needs to be able to SSH into your server without a password.

1.  **On the Pwnagotchi**, generate an SSH key for the `root` user (as the plugin runs as root). Press Enter at all prompts.
    ```bash
    sudo ssh-keygen
    ```

2.  **On the Pwnagotchi**, display the new public key and copy the entire output.
    ```bash
    sudo cat /root/.ssh/id_rsa.pub
    ```

3.  **On your Server**, add the Pwnagotchi's public key to the `authorized_keys` file for the user you specified in `server_user`.
    ```bash
    # Replace 'your-user-on-server' with the actual username
    echo "PASTE_PWNAGOTCHI_PUBLIC_KEY_HERE" >> /home/your-user-on-server/.ssh/authorized_keys
    ```

---

### Step 6: Enable Full Remote Access (Server Firewall)

To access your Pwnagotchi from your home network or from other VPN clients (like your phone), you must configure your WireGuard server's firewall.

1.  **On your WireGuard Server**, enable IP forwarding:
    ```bash
    # Uncomment the net.ipv4.ip_forward=1 line
    sudo nano /etc/sysctl.conf
    # Apply the change immediately
    sudo sysctl -p
    ```

2.  **On your WireGuard Server**, add comprehensive forwarding rules to the WireGuard config file (`/etc/wireguard/wg0.conf`). Replace `eth0` with your server's main LAN interface name.
    ```ini
    # Add these lines under the [Interface] section of wg0.conf
    
    # Rule for VPN clients to access your home LAN and the internet
    PostUp = iptables -A FORWARD -i %i -o eth0 -j ACCEPT; iptables -A FORWARD -i eth0 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    PostDown = iptables -D FORWARD -i %i -o eth0 -j ACCEPT; iptables -D FORWARD -i eth0 -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
    
    # Rule for VPN clients to talk to each other (e.g., phone -> pwnagotchi)
    PostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT
    PostDown = iptables -D FORWARD -i %i -o %i -j ACCEPT
    ```

---

### Step 7: Final Restart and Verification

1.  **On your WireGuard Server**, restart the service to apply the new firewall rules.
    ```bash
    sudo systemctl restart wg-quick@wg0
    ```

2.  **On your Pwnagotchi**, restart the service to load the new plugin and configuration.
    ```bash
    sudo systemctl restart pwnagotchi
    ```

3.  **Verify:**
    * Watch the Pwnagotchi's screen. You should see the `WG:` status change from `Starting` to `Connecting` and then `Up`. After a sync, it will briefly show `Synced: X`.
    * From another machine on your VPN or home LAN, you should be able to access the Pwnagotchi via its VPN IP (e.g., `ssh pi@10.16.244.6` and `http://10.16.244.6:8080`).
    * Check your server. A new folder with your Pwnagotchi's name should be created inside your `remote_base_dir`, containing a `handshakes` subfolder.

---

### Troubleshooting

* **`Permission denied (publickey)` in logs:** The SSH key setup is incorrect. Double-check that the Pwnagotchi's `root` public key was correctly added to the server user's `authorized_keys` file.
* **`Connection timed out`:** A network or firewall issue. Verify both devices are connected to the VPN (`sudo wg show`). Check the server firewall rules from Step 6.
* **`Sync Failed` on screen:** Usually a permission issue on the server. Make sure the `server_user` has permission to write to the `remote_base_dir`.

