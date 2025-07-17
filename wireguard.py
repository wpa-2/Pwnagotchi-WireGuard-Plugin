import logging
import os
import subprocess
import time

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class WireGuard(plugins.Plugin):
    __author__ = 'WPA2 & The Community'
    __version__ = '1.4.0'
    __license__ = 'GPL3'
    __description__ = 'A configurable plugin to connect to WireGuard and sync handshakes with enhanced UI feedback.'

    def __init__(self):
        self.ready = False
        self.status = "Starting"

    def on_loaded(self):
        logging.info("[WireGuard] Plugin loaded.")
        
        # Set default options if they're not in config.toml
        self.options.setdefault('sync_interval_secs', 600)
        self.options.setdefault('source_handshake_path', '/home/pi/handshakes/')
        self.options.setdefault('wg_config_path', '/tmp/wg0.conf')

        # Validate that all required options are present
        required = ['private_key', 'peer_public_key', 'peer_endpoint', 'address', 'server_user', 'handshake_dir']
        missing = [key for key in required if key not in self.options]
        if missing:
            logging.error(f"[WireGuard] Missing required config options: {', '.join(missing)}")
            return
            
        if not os.path.exists('/usr/bin/rsync'):
            logging.error("[WireGuard] rsync is not installed.")
            return
            
        self.ready = True
        self.last_sync_time = 0

    def on_ui_setup(self, ui):
        self.ui = ui
        self.ui.add_element('wg_status', LabeledValue(
            color=BLACK,
            label='WG:',
            value=self.status,
            position=(175, 76),
            label_font=fonts.Small,
            text_font=fonts.Small
        ))

    def _update_status(self, new_status, temporary=False, duration=15):
        """Helper method to update the UI status."""
        original_status = self.status
        self.status = new_status
        self.ui.set('wg_status', self.status)
        self.ui.update()
        
        if temporary:
            time.sleep(duration)
            # Only revert if the status hasn't changed to something else in the meantime
            if self.status == new_status:
                self.status = original_status
                self.ui.set('wg_status', self.status)
                self.ui.update()

    def _connect(self):
        max_retries = 5
        retry_delay = 10
        wg_config_path = self.options['wg_config_path']
        
        for attempt in range(max_retries):
            logging.info(f"[WireGuard] Attempting to connect (Attempt {attempt + 1}/{max_retries})...")
            self._update_status("Connecting")

            try:
                subprocess.run(["wg-quick", "down", wg_config_path], text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                self._update_status("No wg-quick")
                return False
            
            server_vpn_ip = ".".join(self.options['address'].split('.')[:3]) + ".1"
            conf = f"""[Interface]
PrivateKey = {self.options['private_key']}
Address = {self.options['address']}
DNS = {self.options.get('dns', '1.1.1.1')}
[Peer]
PublicKey = {self.options['peer_public_key']}
Endpoint = {self.options['peer_endpoint']}
AllowedIPs = {server_vpn_ip}/32
PersistentKeepalive = 25
"""
            if 'preshared_key' in self.options:
                conf += f"PresharedKey = {self.options['preshared_key']}\n"

            try:
                with open(wg_config_path, "w") as f:
                    f.write(conf)
                os.chmod(wg_config_path, 0o600)
                subprocess.run(["wg-quick", "up", wg_config_path], check=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self._update_status("Up")
                logging.info("[WireGuard] Connection established.")
                return True
            
            except subprocess.CalledProcessError as e:
                stderr_output = e.stderr.strip()
                if "No address associated with hostname" in stderr_output:
                    self._update_status("DNS Retry")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"[WireGuard] Connection failed: {stderr_output}")
                    self._update_status("Error")
                    return False

        logging.error("[WireGuard] Failed to establish connection after multiple retries.")
        self._update_status("Failed")
        return False

    def _sync_handshakes(self):
        logging.info("[WireGuard] Starting handshake sync...")
        self._update_status("Syncing...")
        
        source_dir = self.options['source_handshake_path']
        remote_dir = self.options['handshake_dir']
        server_user = self.options['server_user']
        server_vpn_ip = ".".join(self.options['address'].split('.')[:3]) + ".1"
        
        command = [
            "rsync", "-avz", "--stats", "-e", 
            "ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null",
            source_dir, f"{server_user}@{server_vpn_ip}:{remote_dir}"
        ]

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            new_files = 0
            for line in result.stdout.splitlines():
                if "Number of created files:" in line:
                    new_files = int(line.split(":")[1].strip().split(" ")[0])
                    break
            
            logging.info(f"[WireGuard] Sync complete. Transferred {new_files} new files.")
            self._update_status(f"Synced: {new_files}", temporary=True)
            self.last_sync_time = time.time()

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"[WireGuard] Handshake sync failed: {e}")
            if hasattr(e, 'stderr'):
                logging.error(f"[WireGuard] Stderr: {e.stderr.strip()}")
            self._update_status("Sync Failed", temporary=True)

    def on_internet_available(self, agent):
        if not self.ready:
            return
        
        if self.status not in ["Up", "Connecting", "DNS Retry"]:
            self._connect()
        
        if self.status == "Up":
            now = time.time()
            if now - self.last_sync_time > self.options['sync_interval_secs']:
                self._sync_handshakes()

    def on_unload(self, ui):
        logging.info("[WireGuard] Unloading plugin and disconnecting.")
        wg_config_path = self.options['wg_config_path']
        if os.path.exists(wg_config_path):
            try:
                subprocess.run(["wg-quick", "down", wg_config_path], check=True, capture_output=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
        
        with ui._lock:
            try:
                ui.remove_element('wg_status')
            except KeyError:
                pass
