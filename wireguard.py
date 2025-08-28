import logging
import os
import subprocess
import time

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class WireGuard(plugins.Plugin):
    __author__ = 'WPA2'
    __version__ = '1.0'
    __license__ = 'GPL3'
    __description__ = 'A plugin to connect to WireGuard and sync handshakes with a startup delay and UI notifications.'

    def __init__(self):
        self.ready = False
        self.status = "Initializing"
        self.wg_config_path = "/tmp/wg0.conf"
        self.last_sync_time = 0
        self.sync_interval = 600
        self.initial_boot = True # Flag to run startup sequence only once

    def on_loaded(self):
        logging.info("[WireGuard] Plugin loaded.")
        # Load configurable options or set defaults
        self.options.setdefault('startup_delay_secs', 60)
        
        if 'private_key' not in self.options:
            logging.error("[WireGuard] Configuration is missing. Please edit /etc/pwnagotchi/config.toml")
            return
        if not os.path.exists('/usr/bin/rsync'):
            logging.error("[WireGuard] rsync is not installed. Please run: sudo apt-get install rsync")
            return
        self.ready = True

    def on_ui_setup(self, ui):
        # Store the ui object to use it in other methods
        self.ui = ui
        self.ui.add_element('wg_status', LabeledValue(
            color=BLACK,
            label='WG:',
            value=self.status,
            # FIX 2: Call the width() method with parentheses.
            position=(self.ui.width() // 2 - 25, 0),
            label_font=fonts.Small,
            text_font=fonts.Small
        ))

    def _connect(self):
        logging.info("[WireGuard] Attempting to connect...")
        self.status = "Connecting"
        # FIX 1: Check if self.ui has been initialized before using it.
        if hasattr(self, 'ui'):
            self.ui.set('wg_status', self.status)

        try:
            # Using /dev/null for stdout and stderr to silence the command if it fails because the interface doesn't exist.
            subprocess.run(["wg-quick", "down", self.wg_config_path], capture_output=True)
        except FileNotFoundError:
            logging.error("[WireGuard] `wg-quick` command not found.")
            self.status = "No wg-quick"
            if hasattr(self, 'ui'):
                self.ui.set('wg_status', self.status)
            return False
            
        server_vpn_ip = ".".join(self.options['address'].split('.')[:3]) + ".1"

        conf = f"""[Interface]
PrivateKey = {self.options['private_key']}
Address = {self.options['address']}
"""
        if 'dns' in self.options:
            conf += f"DNS = {self.options['dns']}\n"
        
        conf += f"""
[Peer]
PublicKey = {self.options['peer_public_key']}
Endpoint = {self.options['peer_endpoint']}
AllowedIPs = {server_vpn_ip}/32
PersistentKeepalive = 25
"""

        if 'preshared_key' in self.options:
            conf += f"PresharedKey = {self.options['preshared_key']}\n"

        try:
            with open(self.wg_config_path, "w") as f:
                f.write(conf)
            os.chmod(self.wg_config_path, 0o600)
            subprocess.run(["wg-quick", "up", self.wg_config_path], check=True, capture_output=True, text=True)
            self.status = "Up"
            if hasattr(self, 'ui'):
                self.ui.set('wg_status', self.status)
            logging.info("[WireGuard] Connection established.")
            return True
        except subprocess.CalledProcessError as e:
            self.status = "Error"
            if hasattr(self, 'ui'):
                self.ui.set('wg_status', self.status)
            logging.error(f"[WireGuard] Connection failed: {e}")
            if hasattr(e, 'stderr'):
                stderr_output = e.stderr.replace('\n', ' | ').strip()
                logging.error(f"[WireGuard] Stderr: {stderr_output}")
            return False

    def _sync_handshakes(self):
        logging.info("[WireGuard] Starting handshake sync...")
        
        source_dir = '/home/pi/handshakes/'
        remote_dir = self.options['handshake_dir']
        server_user = self.options['server_user']
        server_vpn_ip = ".".join(self.options['address'].split('.')[:3]) + ".1"
        
        if not os.path.exists(source_dir):
            logging.warning(f"[WireGuard] Source directory {source_dir} not found. Skipping sync.")
            return

        command = [
            "rsync",
            "-avz",
            "--stats",
            "-e", "ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null",
            source_dir,
            f"{server_user}@{server_vpn_ip}:{remote_dir}"
        ]

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            
            new_files = 0
            for line in result.stdout.splitlines():
                if "Number of created files:" in line:
                    try:
                        new_files = int(line.split(":")[1].strip().split(" ")[0])
                        break
                    except (ValueError, IndexError):
                        pass

            if new_files > 0:
                logging.info(f"[WireGuard] Handshake sync to {server_vpn_ip} successful. Transferred {new_files} new files.")
                # FIX 1: Check if self.ui has been initialized.
                if hasattr(self, 'ui'):
                    self.ui.set('wg_status', f"Synced: {new_files}")
            else:
                logging.info(f"[WireGuard] Handshake sync to {server_vpn_ip} successful. No new files to transfer.")
                # FIX 1: Check if self.ui has been initialized.
                if hasattr(self, 'ui'):
                    self.ui.set('wg_status', "Synced: 0")
            
            self.last_sync_time = time.time()
            # After a few seconds, revert the status back to "Up"
            time.sleep(15)
            # Only change back to 'Up' if the status hasn't changed to something else (like 'Connecting')
            if self.status == "Up":
                # FIX 1: Check if self.ui has been initialized.
                if hasattr(self, 'ui'):
                     self.ui.set('wg_status', "Up")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"[WireGuard] Handshake sync failed: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                stderr_output = e.stderr.replace('\n', ' | ').strip()
                logging.error(f"[WireGuard] Stderr: {stderr_output}")

    def on_internet_available(self, agent):
        if not self.ready:
            return

        if self.initial_boot:
            delay = self.options['startup_delay_secs']
            logging.info(f"[WireGuard] Internet detected. Waiting {delay}s for system to settle...")
            time.sleep(delay)
            self.initial_boot = False
        
        if self.status not in ["Up", "Connecting"]:
            self._connect()
        
        if self.status == "Up":
            now = time.time()
            if now - self.last_sync_time > self.sync_interval:
                self._sync_handshakes()

    def on_unload(self, ui):
        logging.info("[WireGuard] Unloading plugin and disconnecting.")
        if os.path.exists(self.wg_config_path):
            try:
                subprocess.run(["wg-quick", "down", self.wg_config_path], check=True, capture_output=True)
                os.remove(self.wg_config_path)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.error(f"[WireGuard] Failed to disconnect: {e}")
        
        with ui._lock:
            try:
                ui.remove_element('wg_status')
            except KeyError:
                pass
