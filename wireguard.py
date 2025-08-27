import logging
import os
import subprocess
import time
import socket # Import socket to get the hostname

import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class WireGuard(plugins.Plugin):
    __author__ = 'WPA2'
    __version__ = '1.8.0'
    __license__ = 'GPL3'
    __description__ = 'A configurable plugin to sync handshakes and backups with optimized performance.'

    def __init__(self):
        self.ready = False
        self.status = "Starting"
        self.hostname = socket.gethostname()

    def on_loaded(self):
        logging.info("[WireGuard] Plugin loaded.")
        
        # Set default options
        self.options.setdefault('sync_interval_secs', 600)
        self.options.setdefault('source_handshake_path', '/home/pi/handshakes/')
        self.options.setdefault('wg_config_path', '/tmp/wg0.conf')
        self.options.setdefault('sync_backup', False)
        self.options.setdefault('source_backup_path', '/home/pi/')

        # Validate required options
        required = ['private_key', 'peer_public_key', 'peer_endpoint', 'address', 'server_user', 'remote_base_dir']
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

    def _update_status(self, new_status):
        """Helper method to update the status variable and the UI element's value."""
        self.status = new_status
        self.ui.set('wg_status', self.status)

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
                conf += f"Preshared_key = {self.options['preshared_key']}\n"

            try:
                with open(wg_config_path, "w") as f:
                    f.write(conf)
                os.chmod(wg_config_path, 0o600)
                subprocess.run(["wg-quick", "up", wg_config_path], check=True, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self._update_status("Up")
                logging.info("[WireGuard] Connection established.")
                return True
            
            except subprocess.CalledProcessError as e:
                stderr_output = e.stderr.strip() if e.stderr else "No stderr output"
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

    def _sync_files(self):
        logging.info("[WireGuard] Starting file sync process...")
        self._update_status("Syncing...")
        
        server_user = self.options['server_user']
        server_vpn_ip = ".".join(self.options['address'].split('.')[:3]) + ".1"
        remote_base_dir = self.options['remote_base_dir']
        
        remote_device_dir = os.path.join(remote_base_dir, self.hostname)
        remote_handshakes_dir = os.path.join(remote_device_dir, "handshakes/")

        try:
            ssh_options = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
            subprocess.run(
                ["ssh"] + ssh_options + [f"{server_user}@{server_vpn_ip}", f"mkdir -p {remote_handshakes_dir}"],
                check=True, capture_output=True, text=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            stderr_output = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else "Could not create remote directory."
            logging.error(f"[WireGuard] Failed to create remote directory: {stderr_output}")
            self._update_status("Sync Failed")
            return

        # Sync Handshakes
        source_handshakes = self.options['source_handshake_path']
        handshake_command = [
            "rsync", "-avz", "--stats", "-e", 
            "ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null",
            source_handshakes, f"{server_user}@{server_vpn_ip}:{remote_handshakes_dir}"
        ]

        try:
            result = subprocess.run(handshake_command, check=True, capture_output=True, text=True)
            new_files = 0
            for line in result.stdout.splitlines():
                if "Number of created files:" in line:
                    num_str = line.split(":")[1].strip().split(" ")[0].replace(',', '')
                    new_files = int(num_str)
                    break
            
            logging.info(f"[WireGuard] Handshake sync complete. Transferred {new_files} new files.")
            self.last_sync_time = time.time()

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            stderr_output = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else "Handshake rsync command failed."
            logging.error(f"[WireGuard] Handshake sync failed: {stderr_output}")
            self._update_status("Sync Failed")

        # Sync Backup File (if enabled)
        if self.options.get('sync_backup', False):
            logging.info("[WireGuard] Starting backup file sync...")
            backup_file_name = f"{self.hostname}-backup.tar.gz"
            backup_file_path = os.path.join(self.options['source_backup_path'], backup_file_name)
            
            if os.path.exists(backup_file_path):
                backup_command = [
                    "rsync", "-avz", "-e",
                    "ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null",
                    backup_file_path, f"{server_user}@{server_vpn_ip}:{remote_device_dir}/"
                ]
                try:
                    subprocess.run(backup_command, check=True, capture_output=True, text=True)
                    logging.info(f"[WireGuard] Backup file '{backup_file_name}' synced successfully.")
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    stderr_output = e.stderr.strip() if hasattr(e, 'stderr') and e.stderr else "Backup rsync command failed."
                    logging.error(f"[WireGuard] Backup file sync failed: {stderr_output}")
            else:
                logging.warning(f"[WireGuard] Backup file not found at '{backup_file_path}', skipping sync.")
        
        # After all sync operations, revert status to Up
        self._update_status("Up")

    def on_internet_available(self, agent):
        if not self.ready:
            return
        
        if self.status not in ["Up", "Connecting", "DNS Retry"]:
            self._connect()
        
        if self.status == "Up":
            now = time.time()
            if now - self.last_sync_time > self.options['sync_interval_secs']:
                self._sync_files()

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
