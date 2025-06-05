import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from tkinter.filedialog import askopenfilename
from network import SecureP2PClient
import crypto_utils as cu
from Crypto.Cipher         import AES
from Crypto.Hash           import SHA256, HMAC, SHAKE128
from Crypto.Util.Padding   import pad, unpad
from Crypto.Random         import get_random_bytes
from Crypto.PublicKey      import ECC

class SecureP2PGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P - Enrollment, Integrity & Session")

        # --- Load Server Keys ---
        enc_path = askopenfilename(title="Select Server Encryption Public Key", filetypes=[("PEM files","*.pem"), ("All files","*.*")])
        if not enc_path:
            messagebox.showerror("Key File Missing","Encryption public key file is required.")
            root.destroy(); return
        sign_path = askopenfilename(title="Select Server Signature Public Key", filetypes=[("PEM files","*.pem"), ("All files","*.*")])
        if not sign_path:
            messagebox.showerror("Key File Missing","Signature public key file is required.")
            root.destroy(); return
        try:
            self.server_enc_pub  = cu.load_rsa_public_key(enc_path)
            self.server_sign_pub = cu.load_rsa_public_key(sign_path)
        except Exception as e:
            messagebox.showerror("Key Load Error", str(e)); root.destroy(); return

        # --- GUI Fields ---
        frame = ttk.Frame(root, padding=10); frame.pack(fill=tk.X)
        ttk.Label(frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(frame); self.ip_entry.grid(row=0, column=1)
        ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_entry = ttk.Entry(frame); self.port_entry.grid(row=1, column=1)
        ttk.Label(frame, text="Student ID:").grid(row=2, column=0, sticky=tk.W)
        self.student_id_entry = ttk.Entry(frame); self.student_id_entry.grid(row=2, column=1)
        ttk.Label(frame, text="Username:").grid(row=3, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(frame); self.username_entry.grid(row=3, column=1)
        ttk.Label(frame, text="Peer ID:").grid(row=4, column=0, sticky=tk.W)
        self.peer_id_entry = ttk.Entry(frame); self.peer_id_entry.grid(row=4, column=1)
        ttk.Label(frame, text="Peer Username:").grid(row=5, column=0, sticky=tk.W)
        self.peer_user_entry = ttk.Entry(frame); self.peer_user_entry.grid(row=5, column=1)

        # --- Buttons ---
        btn_frame = ttk.Frame(root, padding=10); btn_frame.pack(fill=tk.X)
        actions = [
            ("Enroll/Auth", self.handle_enroll),
            ("Disconnect", self.handle_disconnect),
            ("Delete", self.handle_delete),
            ("Get Integrity Key", self.handle_get_ki),
            ("Receive KI", self.handle_receive_ki),
            ("Send DH Params", self.handle_send_dh),
            ("Receive DH Params", self.handle_receive_dh),
            ("Send Message", self.handle_send_message),
            ("Receive Message", self.handle_receive_message)

        ]
        for i, (text, cmd) in enumerate(actions):
            ttk.Button(btn_frame, text=text, command=cmd).grid(row=0, column=i, padx=5)

        # --- Message & Debug windows ---
        self.msg_text = tk.Text(root, height=8, state=tk.DISABLED); self.msg_text.pack(fill=tk.BOTH, expand=True)
        self.debug_text = tk.Text(root, height=8, state=tk.DISABLED); self.debug_text.pack(fill=tk.BOTH, expand=True)

        self.log_message(f"Loaded encryption key from: {enc_path}")
        self.log_message(f"Loaded signature key from: {sign_path}")

        self.client = None


    def handle_enroll(self):
        ip = self.ip_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid port number.")
            return
        sid = self.student_id_entry.get().strip()
        user = self.username_entry.get().strip()
        if not (ip and sid and user):
            messagebox.showerror("Missing Info", "Server IP, Student ID, and Username are required.")
            return

        try:
            self.log_message(f"Connecting to {ip}:{port}...")
            if self.client:
                self.client.close()
            self.client = SecureP2PClient(ip, port)
            self.client.connect()
            self.log_message("Connected.")

            # Auth start
            self.client.send(b"auth")
            self.log_message("Sent 'auth'.")
            raw = self.client.receive()
            sig_len = self.server_sign_pub.size_in_bytes()
            sig = raw[:sig_len]
            msg = raw[sig_len:]
            if not cu.verify_signature(self.server_sign_pub, msg, sig):
                raise ValueError("Invalid signature on start message")
            self.log_message(msg.decode())

            # Credentials
            creds = f"{sid}{user}".encode()
            self.client.send(creds)
            self.log_message(f"Sent credentials: {sid}, {user}")

            raw = self.client.receive()
            sig = raw[:sig_len]; resp = raw[sig_len:]
            if not cu.verify_signature(self.server_sign_pub, resp, sig):
                raise ValueError("Invalid signature on enroll response")
            resp_text = resp.decode()
            self.log_message(resp_text)
            if "error" in resp_text.lower():
                messagebox.showerror("Enroll Error", resp_text)
                return

            # Code prompt
            code = simpledialog.askstring("Verification Code", "Enter the 6-digit code emailed by the server:")
            if not code or not code.isdigit():
                messagebox.showwarning("Invalid Code", "Please enter a valid 6-digit code.")
                return

            self.client.send(b"code")
            self.log_message("Sent 'code'.")
            raw = self.client.receive()
            sig = raw[:sig_len]; ready = raw[sig_len:]
            if not cu.verify_signature(self.server_sign_pub, ready, sig):
                raise ValueError("Invalid signature on ready-for-code message")
            self.log_message(ready.decode())

            # Hash & encrypt KM/IV
            h_val = cu.hash_code(code)
            km, iv = cu.generate_master_iv()
            encrypted = cu.encrypt_master_key(km, iv, self.server_enc_pub)

            payload = h_val + encrypted + creds
            self.client.send(payload)
            self.log_message("Sent hashed code, encrypted KM/IV, credentials.")

            raw = self.client.receive()
            sig = raw[:sig_len]; final = raw[sig_len:]
            if not cu.verify_signature(self.server_sign_pub, final, sig):
                raise ValueError("Invalid signature on final auth message")
            final_text = final.decode()
            self.log_message(final_text)
            if "successful" in final_text.lower():
                self.km, self.iv = km, iv
                self.log_message("Master Key (KM) →")
                self.log_debug(self.km)
                self.log_message("Initialization Vector (IV) →")
                self.log_debug(self.iv)
                messagebox.showinfo("Success", "Enrollment & Authentication completed.")
            else:
                messagebox.showerror("Auth Failed", final_text)

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log_message(f"Error: {e}")

    def handle_disconnect(self):
        if self.client:
            self.client.close()
            self.log_message("Disconnected.")

    def handle_delete(self):
        # Deletion flow: remove enrolled account
        ip = self.ip_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid port number.")
            return
        sid = self.student_id_entry.get().strip()
        user = self.username_entry.get().strip()
        if not (ip and sid and user):
            messagebox.showerror("Missing Info", "Server IP, Student ID, and Username are required for deletion.")
            return

        try:
            # Connect for deletion
            self.log_message(f"Connecting to {ip}:{port} for deletion...")
            if self.client:
                self.client.close()
            self.client = SecureP2PClient(ip, port)
            self.client.connect()
            self.log_message("Connected.")

            # Step 1: send 'delete'
            self.client.send(b"delete")
            self.log_message("Sent 'delete'.")
            raw = self.client.receive()
            sig_len = self.server_sign_pub.size_in_bytes()
            sig = raw[:sig_len]
            msg = raw[sig_len:]
            self.log_debug(sig)
            self.log_debug(msg)
            if not cu.verify_signature(self.server_sign_pub, msg, sig):
                raise ValueError("Invalid signature on delete start message")
            self.log_message(msg.decode())

            # Step 2: send credentials
            creds = f"{sid}{user}".encode()
            self.client.send(creds)
            self.log_message(f"Sent credentials: {sid}, {user}")

            # Step 3: server emails removal code, prompt user
            rcode = simpledialog.askstring("Removal Code", "Enter the removal code emailed by the server:")
            if not rcode:
                messagebox.showwarning("Code Missing", "No removal code entered. Aborting.")
                return

            # Step 4: send 'rcode' literal
            self.client.send(b"rcode")
            self.log_message("Sent 'rcode'.")
            raw = self.client.receive()
            sig = raw[:sig_len]
            ready = raw[sig_len:]
            self.log_debug(sig)
            self.log_debug(ready)
            if not cu.verify_signature(self.server_sign_pub, ready, sig):
                raise ValueError("Invalid signature on ready-for-rcode message")
            self.log_message(ready.decode())

            # Step 5: send rcode + credentials
            payload = rcode.encode() + creds
            self.client.send(payload)
            self.log_message("Sent removal code + credentials.")

            # Final: receive deletion confirmation
            raw = self.client.receive()
            sig = raw[:sig_len]
            final = raw[sig_len:]
            self.log_debug(sig)
            self.log_debug(final)
            if not cu.verify_signature(self.server_sign_pub, final, sig):
                raise ValueError("Invalid signature on final delete message")
            final_text = final.decode()
            self.log_message(final_text)
            messagebox.showinfo("Account Deleted", final_text)

            # Clean up stored KM & IV if present
            if hasattr(self, 'km'):
                del self.km
            if hasattr(self, 'iv'):
                del self.iv

        except Exception as e:
            messagebox.showerror("Deletion Error", str(e))
            self.log_message(f"Error: {e}")

    def handle_get_ki(self):
        ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
        ida = self.student_id_entry.get().strip()
        usera = self.username_entry.get().strip()
        idb = self.peer_id_entry.get().strip()
        userb = self.peer_user_entry.get().strip()
        if not all([ip, port, ida, usera, idb, userb, hasattr(self, 'km'), hasattr(self, 'iv')]):
            messagebox.showerror(
                "Missing Info",
                "Need Server IP, Port, IDs, Usernames, and KM/IV from Step 1"
            )
            return
        try:
            if self.client:
                self.client.close()
            self.client = SecureP2PClient(ip, port)
            self.client.connect()
            N1 = get_random_bytes(16)
            req = f"{ida};{usera};{idb};{userb};".encode() + N1
            self.client.send(req)
            raw = self.client.receive()
            sig_len = self.server_sign_pub.size_in_bytes()
            SID = raw[-16:]
            body = raw[:-16]
            ida_b, idb_b = ida.encode(), idb.encode()
            p1_len = 16 + len(ida_b) + len(idb_b) + 16
            c1_len = ((p1_len + 15) // 16) * 16
            C1, C2 = body[:c1_len], body[c1_len:]
            c2sid = C2 + SID
            self.log_message("C2||SID →  (copy this to your peer)")
            self.log_debug(c2sid)
            iv1 = SHA256.new(self.iv + SID).digest()[:16]
            p1 = unpad(AES.new(self.km, AES.MODE_CBC, iv1).decrypt(C1), AES.block_size)
            KI = p1[:16]
            self.ki = KI
            self.log_message("Integrity Key (KI) →")
            self.log_debug(self.ki)
        except Exception as e:
            messagebox.showerror("KI Distribution Error", str(e))
            self.log_message(f"Error: {e}")

    def handle_receive_ki(self):
        hex_blob = simpledialog.askstring(
            "Paste C2||SID",
            "Paste the hex string of C2||SID from your peer (initiator):"
        )
        if not hex_blob:
            return
        try:
            raw = bytes.fromhex(hex_blob)
        except ValueError:
            messagebox.showerror("Invalid Hex", "That doesn't look like valid hex.")
            return
        c2, sid = raw[:-16], raw[-16:]
        iv2 = SHA256.new(self.iv + sid).digest()[:16]
        try:
            p2 = unpad(AES.new(self.km, AES.MODE_CBC, iv2).decrypt(c2), AES.block_size)
        except ValueError:
            messagebox.showerror("Decryption Error", "Bad padding: wrong key/IV?")
            return
        ki_received = p2[:16]
        ida_echoed = p2[16:].decode()
        expected_ida = self.peer_id_entry.get().strip()
        if expected_ida and ida_echoed != expected_ida:
            messagebox.showerror("Verification Error", f"Expected ID {expected_ida} but got {ida_echoed}")
            return
        self.ki = ki_received
        self.log_message("✓ Peer decrypted C2 and verified Initiator ID")
        self.log_debug(self.ki)
        messagebox.showinfo("Shared Integrity Key", "Step 2 complete: both sides share the same KI.")

    def handle_send_nonce_manual(self):
        """A side: generate N2 and log IV||C3 for manual copy."""
        self.n2 = get_random_bytes(16)
        iv3 = get_random_bytes(16)
        ct3 = iv3 + AES.new(self.ki, AES.MODE_CBC, iv3).encrypt(pad(self.n2, AES.block_size))
        self.log_message("→ Generated and logged E_KI(N2)")
        self.log_message("IV||C3 →  (copy this to your peer)")
        self.log_debug(ct3)

    def handle_receive_nonce_manual(self):
        """B side: paste A's IV||C3, decrypt N2 and build N2-1||N3."""
        hex_blob = simpledialog.askstring("Paste IV||C3", "Paste the IV||C3 hex from initiator:")
        if not hex_blob:
            return
        raw = bytes.fromhex(hex_blob)
        iv3, ct3 = raw[:16], raw[16:]
        N2 = unpad(AES.new(self.ki, AES.MODE_CBC, iv3).decrypt(ct3), AES.block_size)

        N2m1 = (int.from_bytes(N2, 'big') - 1).to_bytes(16, 'big')
        self.n3 = get_random_bytes(16)
        iv4 = get_random_bytes(16)
        ct4 = iv4 + AES.new(self.ki, AES.MODE_CBC, iv4).encrypt(pad(N2m1 + self.n3, AES.block_size))

        self.log_message("← Decrypted N2")
        self.log_message("IV'||C4 →  (copy this back)")
        self.log_debug(ct4)

    def handle_receive_reply_manual(self):
        """A side: paste B's IV'||C4, decrypt and verify N2-1."""
        hex_blob = simpledialog.askstring("Paste IV'||C4", "Paste the IV'||C4 hex from peer:")
        if not hex_blob:
            return
        raw = bytes.fromhex(hex_blob)
        iv4, ct4 = raw[:16], raw[16:]
        data = unpad(AES.new(self.ki, AES.MODE_CBC, iv4).decrypt(ct4), AES.block_size)
        N2m1_recv, N3 = data[:16], data[16:]
        expected = (int.from_bytes(self.n2, 'big') - 1).to_bytes(16, 'big')
        if N2m1_recv != expected:
            messagebox.showerror("Freshness", "N2–1 mismatch! Replay detected.")
            return

        self.log_message("✓ Nonce exchange complete — channel is fresh")
        self.log_debug(N3)
        messagebox.showinfo("Secure Channel", "Step 3 done: you share a fresh channel key!")

    # --- Step3: Diffie-Hellman (ECC P-256) ---
    def handle_send_dh(self):
        """Generate (once) your P-256 keypair, then log pub||HMAC(pub)."""
        # only generate on first call
        if not hasattr(self, 'ec_key'):
            self.ec_key = ECC.generate(curve='P-256')

        # export the public half and MAC it under KI
        pub_der = self.ec_key.public_key().export_key(format='DER')
        mac = HMAC.new(self.ki, pub_der, SHA256).digest()
        blob = pub_der + mac

        # show it to the user
        self.log_message("DH Params →  (copy this to peer)")
        self.log_debug(blob)

    def handle_receive_dh(self):
        """Peer: paste DER||HMAC, verify under KI, derive KS & subkeys"""
        # ensure we already have our own ephemeral keypair
        if not hasattr(self, 'ec_key'):
            self.ec_key = ECC.generate(curve='P-256')
            self.log_message("Generated local ECC keypair")

        hexb = simpledialog.askstring(
            "Paste DH Params",
            "Paste DER||HMAC hex from peer:"
        )
        if not hexb:
            return

        raw      = bytes.fromhex(hexb.strip())
        peer_der = raw[:-32]
        peer_mac = raw[-32:]

        # 3) verify HMAC_KI(peer_pub)
        try:
            HMAC.new(self.ki, peer_der, SHA256).verify(peer_mac)
        except ValueError:
            messagebox.showerror("HMAC Error", "Invalid HMAC on DH Params")
            return

        # 4) import peer’s pubkey and do ECDH
        peer_pub     = ECC.import_key(peer_der)
        shared_pt    = peer_pub.pointQ * self.ec_key.d
        x            = int(shared_pt.x)
        self.ks      = x.to_bytes(32, 'big')

        self.log_message("Derived Session Secret (KS)")
        self.log_debug(self.ks)

        # 5) expand KS→EKAB, EKBA, IKAB, IKBA, IVAB_0, IVBA_0 via one SHAKE128 call
        shake    = SHAKE128.new(self.ks)
        material = shake.read(96)
        labels   = ["EKAB","EKBA","IKAB","IKBA","IVAB_0","IVBA_0"]
        parts    = [material[i*16:(i+1)*16] for i in range(6)]
        self.keys = dict(zip(labels, parts))

        for lab in labels:
            self.log_message(f"{lab} →")
            self.log_debug(self.keys[lab])

        # 6) set initial IV counters
        self.iv_ab = self.keys["IVAB_0"]
        self.iv_ba = self.keys["IVBA_0"]



    # --- Messaging using EKAB/EKBA and IKAB/IKBA ---
    def handle_send_message(self):
        """Encrypt plaintext under EKAB/CBC, HMAC under IKAB, log"""
        text = simpledialog.askstring("Message","Enter text to send:")
        if not text: return
        pt = text.encode()
        iv = self.iv_ab
        ct = AES.new(self.keys['EKAB'], AES.MODE_CBC, iv).encrypt(pad(pt, AES.block_size))
        mac = HMAC.new(self.keys['IKAB'], ct, SHA256).digest()
        blob = iv + ct + mac
        # Rotate IV
        self.iv_ab = SHAKE128.new(self.iv_ab).read(16)
        self.log_message("Cipher||HMAC →  (copy to peer)")
        self.log_debug(blob)
    ##possible problem (add debug statements)
    def handle_receive_message(self):
        """Paste Cipher||HMAC, verify under IKAB and decrypt under EKAB."""
        hexb = simpledialog.askstring("Paste Message", "Paste hex from peer:")
        if not hexb:
            return

        # strip out any accidental spaces or newlines
        hexb = hexb.strip().replace("\n", "").replace(" ", "")

        try:
            raw = bytes.fromhex(hexb)
        except ValueError:
            messagebox.showerror("Hex Error", "That isn't valid hex.")
            return

        # 1) show me the whole blob
        self.log_debug(raw)

        # 2) split into IV / CT / MAC
        iv, ct, mac = raw[:16], raw[16:-32], raw[-32:]
        self.log_debug(f"[recv] iv={len(iv)} ct={len(ct)} mac={len(mac)}")

        # 3) compute what I *should* see
        expected_mac = HMAC.new(self.keys['IKAB'], ct, SHA256).digest()
        self.log_debug(f"[recv] expected_mac = {expected_mac.hex()}")
        self.log_debug(f"[recv]   actual_mac = {mac.hex()}")

        # 4) verify integrity
        try:
            HMAC.new(self.keys['IKAB'], ct, SHA256).verify(mac)
        except ValueError:
            messagebox.showerror("HMAC Error", "Invalid MAC – ciphertext was tampered!")
            return

        # 5) decrypt under EKAB/CBC
        plain = AES.new(self.keys['EKAB'], AES.MODE_CBC, iv).decrypt(ct)
        try:
            plain = unpad(plain, AES.block_size)
        except ValueError:
            messagebox.showerror("Padding Error", "Bad padding on decrypt.")
            return

        # 6) bump your receive-IV for any future replies
        self.iv_ba = SHAKE128.new(self.iv_ba).read(16)

        # 7) show me the plaintext
        try:
            text = plain.decode()
        except UnicodeDecodeError:
            text = f"<binary {plain.hex()}>"
        self.log_message("Decrypted Message → " + text)
        self.log_debug(plain)

    # --- Logging ---
    def log_message(self, msg):
        self.msg_text.config(state=tk.NORMAL)
        self.msg_text.insert(tk.END, msg + "\n")
        self.msg_text.see(tk.END)
        self.msg_text.config(state=tk.DISABLED)

    def log_debug(self, data):
        self.debug_text.config(state=tk.NORMAL)
        if isinstance(data, (bytes, bytearray)):
            s = data.hex()
        else:
            s = str(data)
        self.debug_text.insert(tk.END, s + "\n")
        self.debug_text.see(tk.END)
        self.debug_text.config(state=tk.DISABLED)


