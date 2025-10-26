import os
import psutil
import subprocess
import platform
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import json
import requests

class DownloadMonitor(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
        self.suspicious_extensions = ['.exe', '.msi', '.jar', '.bat', '.cmd', '.scr', '.com', '.pif']
    
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in self.suspicious_extensions:
                self.callback('download_detected', f'Executable file downloaded: {os.path.basename(file_path)}', 3, {'file_path': file_path})

class MonitoringSystem:
    def __init__(self):
        self.running = False
        self.download_observer = None
        # Exact lower-case process names considered suspicious (reduce false positives)
        self.suspicious_process_names = {
            'wireshark.exe', 'nmap.exe', 'sqlmap.py', 'sqlmap.exe', 'john.exe',
            'hashcat.exe', 'aircrack-ng.exe', 'kismet.exe', 'ettercap.exe',
            'cain.exe', 'burpsuite.exe', 'burp.exe', 'hydra.exe', 'metasploit.exe',
            'msfconsole.exe', 'keygen.exe', 'keygen', 'crack.exe', 'exploit.exe'
        }
        # Safe allowlist to ignore common system/browser processes
        self.safe_process_whitelist = {
            'msedgewebview2.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
            'explorer.exe', 'svchost.exe', 'conhost.exe', 'system', 'system idle process',
            'teams.exe', 'onedrive.exe', 'outlook.exe'
        }
        self.usb_devices = []
        self.callback = None
        self.enable_downloads = True
        # Track last seen USB device IDs to emit only changes (more professional, no spam)
        self._last_usb_device_ids = set()
        # Exclude common non-removable or noisy USB classes
        self.usb_exclude_keywords = {
            'root hub', 'composite device', 'bluetooth', 'keyboard', 'mouse',
            'receiver', 'hid', 'usb input device', 'camera', 'webcam'
        }
        # Network/IP change detection state
        self.last_public_ip = None
        self.last_default_gateway = None
        self._last_public_ip_check_ts = 0
    
    def set_callback(self, callback):
        self.callback = callback
    
    def start(self):
        self.running = True
        
        # Start download monitoring if enabled
        if self.enable_downloads:
            downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
            if os.path.exists(downloads_path):
                self.download_observer = Observer()
                self.download_observer.schedule(DownloadMonitor(self.create_incident), downloads_path, recursive=False)
                self.download_observer.start()
        
        print("Monitoring system started")
    
    def stop(self):
        self.running = False
        if self.download_observer:
            self.download_observer.stop()
            self.download_observer.join()
        print("Monitoring system stopped")
    
    def create_incident(self, event_type, description, severity, metadata=None):
        if self.callback:
            self.callback(event_type, description, severity, metadata)
    
    def check_suspicious_processes(self):
        suspicious_found = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    name_raw = proc_info.get('name') or ''
                    proc_name = name_raw.lower()

                    # Skip safe processes
                    if proc_name in self.safe_process_whitelist:
                        continue

                    # Only flag exact-name matches from the suspicious set
                    if proc_name in self.suspicious_process_names:
                        suspicious_found.append({
                            'pid': proc_info.get('pid'),
                            'name': name_raw,
                            'cmdline': proc_info.get('cmdline')
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error checking processes: {e}")
        
        return suspicious_found
    
    def check_vpn_interfaces(self):
        vpn_interfaces = []
        try:
            if platform.system() == "Windows":
                # Check for VPN interfaces on Windows
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'tun' in line.lower() or 'tap' in line.lower() or 'vpn' in line.lower():
                            vpn_interfaces.append(line.strip())
            else:
                # Check for VPN interfaces on Linux/Mac
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'tun' in line.lower() or 'tap' in line.lower():
                            vpn_interfaces.append(line.strip())
        except Exception as e:
            print(f"Error checking VPN interfaces: {e}")
        
        return vpn_interfaces
    
    def _get_current_usb_devices(self):
        devices = []
        try:
            if platform.system() == "Windows":
                try:
                    import wmi
                    import pythoncom
                    pythoncom.CoInitialize()
                    c = wmi.WMI()
                    # Prefer disk drives that are truly removable
                    for dd in c.Win32_DiskDrive(InterfaceType='USB'):
                        pnp_id = dd.PNPDeviceID or dd.DeviceID or ''
                        name = (dd.Model or dd.Caption or 'USB Storage').strip()
                        if any(k in name.lower() for k in self.usb_exclude_keywords):
                            continue
                        devices.append({
                            'name': name,
                            'device_id': pnp_id,
                            'status': 'Connected',
                            'class': 'DiskDrive'
                        })
                    # As a fallback, include logical removable disks (DriveType=2)
                    for ld in c.Win32_LogicalDisk(DriveType=2):
                        name = f"Removable Disk {ld.DeviceID}"
                        devid = ld.DeviceID
                        devices.append({
                            'name': name,
                            'device_id': devid,
                            'status': 'Connected',
                            'class': 'LogicalDisk'
                        })
                    pythoncom.CoUninitialize()
                except ImportError:
                    # Minimal fallback via WMIC
                    result = subprocess.run(['wmic', 'diskdrive', 'where', 'InterfaceType="USB"', 'get', 'Model,PNPDeviceID'],
                                            capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines()[1:]:
                            line = line.strip()
                            if not line:
                                continue
                            if any(k in line.lower() for k in self.usb_exclude_keywords):
                                continue
                            devices.append({'name': line, 'device_id': line, 'status': 'Connected', 'class': 'DiskDrive'})
            else:
                # Linux/macOS: list block devices from lsblk/lsusb as approximation
                result = subprocess.run(['lsblk', '-o', 'NAME,TRAN,RM,MOUNTPOINT'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.splitlines()[1:]:
                        cols = [c for c in line.split() if c]
                        if len(cols) >= 3 and (cols[1].lower() == 'usb' or cols[2] == '1'):
                            devices.append({'name': cols[0], 'device_id': cols[0], 'status': 'Connected', 'class': 'Block'})
        except Exception as e:
            print(f"Error checking USB devices: {e}")
        return devices

    def check_usb_devices(self):
        """Return only changes since last call: list of events with action connected/disconnected."""
        events = []
        current = self._get_current_usb_devices()
        current_ids = {d.get('device_id') for d in current if d.get('device_id')}

        # Newly connected
        for dev in current:
            dev_id = dev.get('device_id')
            if dev_id and dev_id not in self._last_usb_device_ids:
                events.append({'action': 'connected', 'name': dev.get('name'), 'device_id': dev_id, 'class': dev.get('class')})

        # Disconnected
        for old_id in (self._last_usb_device_ids - current_ids):
            events.append({'action': 'disconnected', 'device_id': old_id})

        self._last_usb_device_ids = current_ids
        return events

    def _get_public_ip(self):
        try:
            resp = requests.get('https://api.ipify.org', timeout=3)
            if resp.status_code == 200:
                return resp.text.strip()
        except Exception:
            return None

    def _get_default_gateway_windows(self):
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
            gw = None
            for line in result.stdout.splitlines():
                if 'Default Gateway' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        candidate = parts[1].strip()
                        if candidate:
                            gw = candidate
            return gw
        except Exception:
            return None

    def _get_default_gateway_unix(self):
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                if line.startswith('default via '):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
            return None
        except Exception:
            return None

    def check_ip_change(self):
        """Check for sudden public IP and gateway changes. Returns list of events."""
        events = []
        # Public IP check (rate-limit to ~once per 30s)
        now = time.time()
        if now - self._last_public_ip_check_ts >= 30:
            self._last_public_ip_check_ts = now
            public_ip = self._get_public_ip()
            if public_ip and self.last_public_ip and public_ip != self.last_public_ip:
                events.append({'type': 'public_ip_changed', 'old': self.last_public_ip, 'new': public_ip})
            if public_ip:
                self.last_public_ip = public_ip

        # Default gateway check
        if platform.system() == 'Windows':
            gw = self._get_default_gateway_windows()
        else:
            gw = self._get_default_gateway_unix()
        if gw and self.last_default_gateway and gw != self.last_default_gateway:
            events.append({'type': 'gateway_changed', 'old': self.last_default_gateway, 'new': gw})
        if gw:
            self.last_default_gateway = gw

        return events
    
    def get_status(self):
        return {
            'running': self.running,
            'download_monitoring': self.download_observer is not None and self.download_observer.is_alive(),
            'process_monitoring': True,
            'network_monitoring': True,
            'usb_monitoring': True
        }

    def set_downloads_enabled(self, enabled: bool):
        enabled = bool(enabled)
        if enabled == self.enable_downloads:
            return
        self.enable_downloads = enabled
        # Toggle observer accordingly
        try:
            if not enabled and self.download_observer:
                self.download_observer.stop()
                self.download_observer.join()
                self.download_observer = None
            elif enabled and self.download_observer is None:
                downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
                if os.path.exists(downloads_path):
                    self.download_observer = Observer()
                    self.download_observer.schedule(DownloadMonitor(self.create_incident), downloads_path, recursive=False)
                    self.download_observer.start()
        except Exception as e:
            print(f"Error toggling downloads monitoring: {e}")
