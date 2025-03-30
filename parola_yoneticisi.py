import secrets
import string
import os
import sqlite3
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import customtkinter as ctk
from tkinter import messagebox
import pyperclip
from datetime import datetime, timedelta
import json
import logging
import shutil

# Günlükleme yapılandırması
logging.basicConfig(
    filename='password_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Konfigürasyon dosyasını yükleme
def load_config():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "key_file": "anahtar.key",
            "hash_file": "parola_hash.txt",
            "secret_question_file": "gizli_soru.txt",
            "database_file": "passwords.db",
            "min_password_length": 12,
            "pbkdf2_iterations": 600000,
            "language_file": "dil_secimi.json"
        }

config = load_config()
ANAHTAR_DOSYASI = config["key_file"]
HASH_DOSYASI = config["hash_file"]
GIZLI_SORU_DOSYASI = config["secret_question_file"]
VERITABANI = config["database_file"]
MIN_PAROLA_UZUNLUK = config["min_password_length"]
PBKDF2_ITERASYON = config["pbkdf2_iterations"]
DIL_SECIMI_DOSYASI = config["language_file"]

# Dil sözlüğü
LANGUAGE_DICT = {
    "tr": {
        "title": "Güvenli Parola Yöneticisi",
        "login_title": "ANA PAROLA GİRİŞ",
        "password_label": "Ana Parola:",
        "login_button": "Giriş Yap",
        "forgot_password": "Parolamı Unuttum",
        "secret_question_title": "GİZLİ SORU AYARLA",
        "secret_question_label": "Gizli Soru: İlk evcil hayvanınızın ismi nedir?",
        "answer_label": "Cevap:",
        "save_button": "Kaydet",
        "recovery_title": "PAROLA KURTARMA",
        "recovery_question_label": "Soru: İlk evcil hayvanınızın ismi nedir?",
        "new_password_label": "Yeni Parola:",
        "new_password_repeat_label": "Yeni Parola Tekrar:",
        "reset_button": "Sıfırla",
        "main_screen_title": "PAROLA YÖNETİCİSİ",
        "generate_password_label": "Yeni Parola Oluştur",
        "category_label": "Kategori:",
        "description_label": "Açıklama:",
        "length_label": "Uzunluk:",
        "generate_save_button": "Üret ve Kaydet",
        "filter_label": "Filtrele:",
        "search_label": "Arama...",
        "filter_button": "Filtrele",
        "show_hide_button": "Göster/Gizle",
        "copy_button": "Kopyala",
        "delete_button": "Sil",
        "backup_button": "Yedekle",
        "exit_button": "Çıkış",
        "success_message": "Başarılı",
        "error_message": "Hata",
        "password_saved": " için parola kaydedildi!\nGüç: ",
        "password_copied": "Parola panoya kopyalandı!",
        "password_deleted": "Parola silindi!",
        "backup_created": "Yedek oluşturuldu: ",
        "select_password": "Lütfen bir parola seçin!",
        "password_not_found": "Parola bulunamadı!",
        "fill_all_fields": "Lütfen tüm alanları doldurun!",
        "passwords_do_not_match": "Yeni parolalar eşleşmiyor!",
        "wrong_answer": "Yanlış cevap!",
        "secret_question_not_found": "Gizli soru bulunamadı! İlk önce ana parola oluşturmalısınız.",
        "password_reset_success": "Parola başarıyla sıfırlandı!",
        "password_reset_error": "Sıfırlama hatası: ",
        "password_save_error": "Parola kaydetme hatası: ",
        "backup_error": "Yedekleme hatası: ",
        "categories": ["Tümü", "Kişisel", "İş", "Eğlence", "Diğer"]
    },
    "en": {
        "title": "Secure Password Manager",
        "login_title": "MASTER PASSWORD LOGIN",
        "password_label": "Master Password:",
        "login_button": "Login",
        "forgot_password": "Forgot Password",
        "secret_question_title": "SET SECRET QUESTION",
        "secret_question_label": "Secret Question: What is the name of your first pet?",
        "answer_label": "Answer:",
        "save_button": "Save",
        "recovery_title": "PASSWORD RECOVERY",
        "recovery_question_label": "Question: What is the name of your first pet?",
        "new_password_label": "New Password:",
        "new_password_repeat_label": "Repeat New Password:",
        "reset_button": "Reset",
        "main_screen_title": "PASSWORD MANAGER",
        "generate_password_label": "Generate New Password",
        "category_label": "Category:",
        "description_label": "Description:",
        "length_label": "Length:",
        "generate_save_button": "Generate and Save",
        "filter_label": "Filter:",
        "search_label": "Search...",
        "filter_button": "Filter",
        "show_hide_button": "Show/Hide",
        "copy_button": "Copy",
        "delete_button": "Delete",
        "backup_button": "Backup",
        "exit_button": "Exit",
        "success_message": "Success",
        "error_message": "Error",
        "password_saved": " password saved for!\nStrength: ",
        "password_copied": "Password copied to clipboard!",
        "password_deleted": "Password deleted!",
        "backup_created": "Backup created: ",
        "select_password": "Please select a password!",
        "password_not_found": "Password not found!",
        "fill_all_fields": "Please fill all fields!",
        "passwords_do_not_match": "New passwords do not match!",
        "wrong_answer": "Wrong answer!",
        "secret_question_not_found": "Secret question not found! Please set the master password first.",
        "password_reset_success": "Password reset successfully!",
        "password_reset_error": "Reset error: ",
        "password_save_error": "Password save error: ",
        "backup_error": "Backup error: ",
        "categories": ["All", "Personal", "Work", "Entertainment", "Other"]
    }
}

class PasswordManagerLogic:
    def __init__(self):
        self.fernet = None
        self._init_db()
        self._anahtar_yonet()

    def _init_db(self):
        with sqlite3.connect(VERITABANI) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    kategori TEXT NOT NULL,
                    aciklama TEXT NOT NULL,
                    parola TEXT NOT NULL,
                    olusturulma_tarihi TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

    def _anahtar_yonet(self):
        if os.path.exists(ANAHTAR_DOSYASI):
            try:
                with open(ANAHTAR_DOSYASI, "rb") as f:
                    anahtar = f.read()
                Fernet(anahtar)
                self.fernet = Fernet(anahtar)
            except (ValueError, InvalidToken):
                self._yeni_anahtar_olustur()
        else:
            self._yeni_anahtar_olustur()

    def _yeni_anahtar_olustur(self):
        anahtar = Fernet.generate_key()
        with open(ANAHTAR_DOSYASI, "wb") as f:
            f.write(anahtar)
        self.fernet = Fernet(anahtar)

    def parola_hashle(self, parola):
        tuz = os.urandom(32)
        hash = hashlib.pbkdf2_hmac('sha256', parola.encode(), tuz, PBKDF2_ITERASYON)
        return tuz.hex() + hash.hex()

    def parola_dogrula(self, parola, saklanan_hash):
        try:
            tuz = bytes.fromhex(saklanan_hash[:64])
            hash = hashlib.pbkdf2_hmac('sha256', parola.encode(), tuz, PBKDF2_ITERASYON)
            return hash.hex() == saklanan_hash[64:]
        except ValueError:
            return False

    def parola_uret(self, uzunluk=MIN_PAROLA_UZUNLUK):
        if uzunluk < MIN_PAROLA_UZUNLUK:
            raise ValueError(f"Password length must be at least {MIN_PAROLA_UZUNLUK} characters!")
        
        karakterler = string.ascii_letters + string.digits + string.punctuation
        while True:
            parola = ''.join(secrets.choice(karakterler) for _ in range(uzunluk))
            if (any(c.isupper() for c in parola) and 
                any(c.islower() for c in parola) and 
                any(c.isdigit() for c in parola) and 
                any(c in string.punctuation for c in parola)):
                return parola

    def parola_guc_analizi(self, parola):
        karakter_tipi_sayisi = 0
        if any(c.isupper() for c in parola):
            karakter_tipi_sayisi += 26
        if any(c.islower() for c in parola):
            karakter_tipi_sayisi += 26
        if any(c.isdigit() for c in parola):
            karakter_tipi_sayisi += 10
        if any(c in string.punctuation for c in parola):
            karakter_tipi_sayisi += 32
        
        entropi = len(parola) * (karakter_tipi_sayisi.bit_length() - 1)
        if entropi < 50:
            return "Zayıf" if LANGUAGE_DICT["tr"] else "Weak"
        elif entropi < 80:
            return "Orta" if LANGUAGE_DICT["tr"] else "Medium"
        else:
            return "Güçlü" if LANGUAGE_DICT["tr"] else "Strong"

    def parola_kaydet(self, kategori, aciklama, parola, user_id):
        if not aciklama:
            raise ValueError("Description cannot be empty!")
        
        sifreli_parola = self.fernet.encrypt(parola.encode()).decode()
        
        with sqlite3.connect(VERITABANI) as conn:
            try:
                conn.execute(
                    "INSERT INTO passwords (user_id, kategori, aciklama, parola) VALUES (?, ?, ?, ?)",
                    (user_id, kategori, aciklama, sifreli_parola)
                )
                logging.info(f"Password saved: {aciklama} (Category: {kategori}, User ID: {user_id})")
            except sqlite3.IntegrityError:
                logging.error(f"Duplicate description attempted: {aciklama}")
                raise ValueError("This description already exists!")

    def parola_listele(self, user_id):
        with sqlite3.connect(VERITABANI) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, kategori, aciklama, parola, olusturulma_tarihi FROM passwords WHERE user_id = ?", (user_id,))
            rows = cursor.fetchall()
        
        parolalar = []
        for row in rows:
            password_id, kategori, aciklama, encrypted_password, created_at = row
            try:
                parola = self.fernet.decrypt(encrypted_password.encode()).decode()
                parolalar.append((password_id, kategori, aciklama, parola, created_at))
            except InvalidToken:
                continue
        return parolalar

    def parola_sil(self, password_id):
        with sqlite3.connect(VERITABANI) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            conn.commit()
            if cursor.rowcount > 0:
                logging.info(f"Password deleted: ID {password_id}")
                return True
            return False

    def parola_suresi_kontrol(self, created_at):
        try:
            created_date = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            return datetime.now() > created_date + timedelta(days=90)
        except ValueError:
            return False

    def yedekle(self):
        yedek_dosya = f"backup_{VERITABANI}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy(VERITABANI, yedek_dosya)
        logging.info(f"Database backed up: {yedek_dosya}")
        return yedek_dosya

    def gizli_soru_kaydet(self, cevap):
        hashed_cevap = self.parola_hashle(cevap)
        with open(GIZLI_SORU_DOSYASI, "w") as f:
            f.write(hashed_cevap)
        logging.info("Secret answer saved")

    def gizli_soru_getir(self):
        if not os.path.exists(GIZLI_SORU_DOSYASI):
            return None
        with open(GIZLI_SORU_DOSYASI, "r") as f:
            hashed_cevap = f.read().strip()
        return hashed_cevap

    def ana_parola_sifirla(self, yeni_parola):
        if messagebox.askyesno("Confirm", "Master password will be reset, and all data will be deleted. Do you want to continue?"):
            with open(HASH_DOSYASI, "w") as f:
                f.write(self.parola_hashle(yeni_parola))
            if os.path.exists(VERITABANI):
                os.remove(VERITABANI)
            if os.path.exists(ANAHTAR_DOSYASI):
                os.remove(ANAHTAR_DOSYASI)
            if os.path.exists(GIZLI_SORU_DOSYASI):
                os.remove(GIZLI_SORU_DOSYASI)
            self._init_db()
            self._anahtar_yonet()
            logging.info("Master password reset and database recreated")

class ParolaYoneticisi(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.logic = PasswordManagerLogic()
        self.title("Güvenli Parola Yöneticisi")
        self.geometry("600x800")
        self.parolalar_goster = False
        self.secili_password_id = None
        self.user_id = None
        self.current_language = self._load_language()
        self._arayuz_olustur()

    def _load_language(self):
        if os.path.exists(DIL_SECIMI_DOSYASI):
            with open(DIL_SECIMI_DOSYASI, "r") as f:
                data = json.load(f)
                return data.get("language", "tr")
        return "tr"

    def _save_language(self, lang):
        with open(DIL_SECIMI_DOSYASI, "w") as f:
            json.dump({"language": lang}, f)

    def _set_language(self, lang):
        self.current_language = lang
        self._save_language(lang)
        self._update_ui_language()

    def _update_ui_language(self):
        lang = LANGUAGE_DICT[self.current_language]
        self.title(lang["title"])
        if hasattr(self, "login_title_label"):
            self.login_title_label.configure(text=lang["login_title"])
        if hasattr(self, "password_label"):
            self.password_label.configure(text=lang["password_label"])
        if hasattr(self, "login_button"):
            self.login_button.configure(text=lang["login_button"])
        if hasattr(self, "forgot_password_button"):
            self.forgot_password_button.configure(text=lang["forgot_password"])
        if hasattr(self, "secret_question_title_label"):
            self.secret_question_title_label.configure(text=lang["secret_question_title"])
        if hasattr(self, "secret_question_label"):
            self.secret_question_label.configure(text=lang["secret_question_label"])
        if hasattr(self, "answer_label"):
            self.answer_label.configure(text=lang["answer_label"])
        if hasattr(self, "save_button"):
            self.save_button.configure(text=lang["save_button"])
        if hasattr(self, "recovery_title_label"):
            self.recovery_title_label.configure(text=lang["recovery_title"])
        if hasattr(self, "recovery_question_label"):
            self.recovery_question_label.configure(text=lang["recovery_question_label"])
        if hasattr(self, "new_password_label"):
            self.new_password_label.configure(text=lang["new_password_label"])
        if hasattr(self, "new_password_repeat_label"):
            self.new_password_repeat_label.configure(text=lang["new_password_repeat_label"])
        if hasattr(self, "reset_button"):
            self.reset_button.configure(text=lang["reset_button"])
        if hasattr(self, "generate_password_label"):
            self.generate_password_label.configure(text=lang["generate_password_label"])
        if hasattr(self, "category_label"):
            self.category_label.configure(text=lang["category_label"])
        if hasattr(self, "description_label"):
            self.description_label.configure(text=lang["description_label"])
        if hasattr(self, "length_label"):
            self.length_label.configure(text=lang["length_label"])
        if hasattr(self, "generate_save_button"):
            self.generate_save_button.configure(text=lang["generate_save_button"])
        if hasattr(self, "filter_label"):
            self.filter_label.configure(text=lang["filter_label"])
        if hasattr(self, "search_label"):
            self.search_label.configure(text=lang["search_label"])
        if hasattr(self, "filter_button"):
            self.filter_button.configure(text=lang["filter_button"])
        if hasattr(self, "show_hide_button"):
            self.show_hide_button.configure(text=lang["show_hide_button"])
        if hasattr(self, "copy_button"):
            self.copy_button.configure(text=lang["copy_button"])
        if hasattr(self, "delete_button"):
            self.delete_button.configure(text=lang["delete_button"])
        if hasattr(self, "backup_button"):
            self.backup_button.configure(text=lang["backup_button"])
        if hasattr(self, "exit_button"):
            self.exit_button.configure(text=lang["exit_button"])
        if hasattr(self, "filtre_secim"):
            self.filtre_secim.configure(values=lang["categories"])

    def _arayuz_olustur(self):
        self._giris_ekrani()

    def _giris_ekrani(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.grid_columnconfigure(0, weight=1)
        
        # Dil seçim menüsü
        self.language_menu = ctk.CTkComboBox(self, values=["Türkçe", "English"], command=self._change_language)
        self.language_menu.grid(row=0, column=0, sticky="ne", padx=10, pady=10)
        self.language_menu.set("Türkçe" if self.current_language == "tr" else "English")
        
        lang = LANGUAGE_DICT[self.current_language]
        
        self.login_title_label = ctk.CTkLabel(self, text=lang["login_title"], font=("Arial", 20, "bold"))
        self.login_title_label.grid(row=1, column=0, pady=20)
        
        self.password_label = ctk.CTkLabel(self, text=lang["password_label"])
        self.password_label.grid(row=2, column=0, pady=5)
        self.ana_parola_girdi = ctk.CTkEntry(self, show="*", width=250)
        self.ana_parola_girdi.grid(row=3, column=0, pady=5)
        
        self.login_button = ctk.CTkButton(self, text=lang["login_button"], command=self._giris_kontrol, fg_color="#2E8B57")
        self.login_button.grid(row=4, column=0, pady=10)
        self.forgot_password_button = ctk.CTkButton(self, text=lang["forgot_password"], command=self._parola_kurtarma_ekrani, fg_color="#FF4500")
        self.forgot_password_button.grid(row=5, column=0, pady=10)

    def _change_language(self, choice):
        if choice == "Türkçe":
            self._set_language("tr")
        elif choice == "English":
            self._set_language("en")

    def _giris_kontrol(self):
        ana_parola = self.ana_parola_girdi.get()
        
        if not ana_parola:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["fill_all_fields"])
            return
        
        with sqlite3.connect(VERITABANI) as conn:
            cursor = conn.execute("SELECT id, password_hash FROM users")
            result = cursor.fetchone()
            if result:
                if self.logic.parola_dogrula(ana_parola, result[1]):
                    self.user_id = result[0]
                    logging.info("Login successful")
                    self._ana_ekran()
                else:
                    logging.warning("Invalid password attempt")
                    messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["wrong_answer"])
            else:
                # İlk giriş, gizli soru ekranını aç
                self._gizli_soru_ekrani(ana_parola)

    def _gizli_soru_ekrani(self, ana_parola):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.grid_columnconfigure(0, weight=1)
        
        lang = LANGUAGE_DICT[self.current_language]
        
        self.secret_question_title_label = ctk.CTkLabel(self, text=lang["secret_question_title"], font=("Arial", 20, "bold"))
        self.secret_question_title_label.grid(row=0, column=0, pady=20)
        
        self.secret_question_label = ctk.CTkLabel(self, text=lang["secret_question_label"])
        self.secret_question_label.grid(row=1, column=0, pady=5)
        
        self.answer_label = ctk.CTkLabel(self, text=lang["answer_label"])
        self.answer_label.grid(row=2, column=0, pady=5)
        self.gizli_cevap_girdi = ctk.CTkEntry(self, width=250)
        self.gizli_cevap_girdi.grid(row=3, column=0, pady=5)
        
        self.save_button = ctk.CTkButton(self, text=lang["save_button"], command=lambda: self._gizli_soru_kaydet(ana_parola), 
                                         fg_color="#2E8B57")
        self.save_button.grid(row=4, column=0, pady=20)

    def _gizli_soru_kaydet(self, ana_parola):
        cevap = self.gizli_cevap_girdi.get()
        
        if not cevap:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["fill_all_fields"])
            return
            
        try:
            self.logic.gizli_soru_kaydet(cevap)
            with sqlite3.connect(VERITABANI) as conn:
                password_hash = self.logic.parola_hashle(ana_parola)
                conn.execute("INSERT INTO users (password_hash) VALUES (?)", (password_hash,))
                self.user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            with open(HASH_DOSYASI, "w") as f:
                f.write(password_hash)
            messagebox.showinfo(LANGUAGE_DICT[self.current_language]["success_message"], "Master password and secret question saved!")
            self._giris_ekrani()
        except Exception as e:
            logging.error(f"Save error: {str(e)}")
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], f"Save error: {str(e)}")

    def _parola_kurtarma_ekrani(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.grid_columnconfigure(0, weight=1)
        
        lang = LANGUAGE_DICT[self.current_language]
        
        hashed_cevap = self.logic.gizli_soru_getir()
        if not hashed_cevap:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["secret_question_not_found"])
            self._giris_ekrani()
            return
            
        self.recovery_title_label = ctk.CTkLabel(self, text=lang["recovery_title"], font=("Arial", 20, "bold"))
        self.recovery_title_label.grid(row=0, column=0, pady=20)
        
        self.recovery_question_label = ctk.CTkLabel(self, text=lang["recovery_question_label"])
        self.recovery_question_label.grid(row=1, column=0, pady=10)
        
        self.answer_label = ctk.CTkLabel(self, text=lang["answer_label"])
        self.answer_label.grid(row=2, column=0, pady=5)
        self.cevap_girdi = ctk.CTkEntry(self, width=250)
        self.cevap_girdi.grid(row=3, column=0, pady=5)
        
        self.new_password_label = ctk.CTkLabel(self, text=lang["new_password_label"])
        self.new_password_label.grid(row=4, column=0, pady=5)
        self.yeni_parola_girdi = ctk.CTkEntry(self, show="*", width=250)
        self.yeni_parola_girdi.grid(row=5, column=0, pady=5)
        
        self.new_password_repeat_label = ctk.CTkLabel(self, text=lang["new_password_repeat_label"])
        self.new_password_repeat_label.grid(row=6, column=0, pady=5)
        self.yeni_parola_tekrar_girdi = ctk.CTkEntry(self, show="*", width=250)
        self.yeni_parola_tekrar_girdi.grid(row=7, column=0, pady=5)
        
        self.reset_button = ctk.CTkButton(self, text=lang["reset_button"], command=self._parola_sifirla, 
                                          fg_color="#2E8B57")
        self.reset_button.grid(row=8, column=0, pady=20)

    def _parola_sifirla(self):
        cevap = self.cevap_girdi.get()
        yeni_parola = self.yeni_parola_girdi.get()
        yeni_parola_tekrar = self.yeni_parola_tekrar_girdi.get()
        
        if not cevap or not yeni_parola or not yeni_parola_tekrar:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["fill_all_fields"])
            return
        
        if yeni_parola != yeni_parola_tekrar:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["passwords_do_not_match"])
            return
        
        hashed_cevap = self.logic.gizli_soru_getir()
        if not hashed_cevap:
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["secret_question_not_found"])
            return
            
        if not self.logic.parola_dogrula(cevap, hashed_cevap):
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], LANGUAGE_DICT[self.current_language]["wrong_answer"])
            return
            
        try:
            self.logic.ana_parola_sifirla(yeni_parola)
            messagebox.showinfo(LANGUAGE_DICT[self.current_language]["success_message"], LANGUAGE_DICT[self.current_language]["password_reset_success"])
            self._giris_ekrani()
        except Exception as e:
            logging.error(f"Reset error: {str(e)}")
            messagebox.showerror(LANGUAGE_DICT[self.current_language]["error_message"], f"{LANGUAGE_DICT[self.current_language]['password_reset_error']}{str(e)}")

    def _ana_ekran(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.grid_columnconfigure(0, weight=1)
        
        lang = LANGUAGE_DICT[self.current_language]
        
        # Dil seçim menüsü
        self.language_menu = ctk.CTkComboBox(self, values=["Türkçe", "English"], command=self._change_language)
        self.language_menu.grid(row=0, column=0, sticky="ne", padx=10, pady=10)
        self.language_menu.set("Türkçe" if self.current_language == "tr" else "English")
        
        # Üst Kontrol Paneli
        kontrol_frame = ctk.CTkFrame(self)
        kontrol_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        self.generate_password_label = ctk.CTkLabel(kontrol_frame, text=lang["generate_password_label"], font=("Arial", 14, "bold"))
        self.generate_password_label.grid(row=0, column=0, padx=5)
        
        self.category_label = ctk.CTkLabel(kontrol_frame, text=lang["category_label"])
        self.category_label.grid(row=0, column=1, padx=5)
        self.kategori_secim = ctk.CTkComboBox(kontrol_frame, values=lang["categories"][1:])  # "Tümü" hariç
        self.kategori_secim.grid(row=0, column=2, padx=5)
        
        self.description_label = ctk.CTkLabel(kontrol_frame, text=lang["description_label"])
        self.description_label.grid(row=0, column=3, padx=5)
        self.aciklama_girdi = ctk.CTkEntry(kontrol_frame, placeholder_text=lang["description_label"])
        self.aciklama_girdi.grid(row=0, column=4, padx=5)
        
        self.length_label = ctk.CTkLabel(kontrol_frame, text=lang["length_label"])
        self.length_label.grid(row=0, column=5, padx=5)
        self.uzunluk_girdi = ctk.CTkEntry(kontrol_frame, width=50, placeholder_text=str(MIN_PAROLA_UZUNLUK))
        self.uzunluk_girdi.grid(row=0, column=6, padx=5)
        
        self.generate_save_button = ctk.CTkButton(kontrol_frame, text=lang["generate_save_button"], command=self._parola_kaydet, 
                                                  fg_color="#2E8B57")
        self.generate_save_button.grid(row=0, column=7, padx=5)
        
        # Filtre ve Arama
        filtre_frame = ctk.CTkFrame(self)
        filtre_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        self.filter_label = ctk.CTkLabel(filtre_frame, text=lang["filter_label"])
        self.filter_label.grid(row=0, column=0, padx=5)
        self.filtre_secim = ctk.CTkComboBox(filtre_frame, values=lang["categories"])
        self.filtre_secim.grid(row=0, column=1, padx=5)
        self.filtre_secim.set(lang["categories"][0])
        
        self.search_label = ctk.CTkLabel(filtre_frame, text=lang["search_label"])
        self.search_label.grid(row=0, column=2, padx=5)
        self.arama_girdi = ctk.CTkEntry(filtre_frame, placeholder_text=lang["search_label"])
        self.arama_girdi.grid(row=0, column=3, padx=5)
        
        self.filter_button = ctk.CTkButton(filtre_frame, text=lang["filter_button"], command=self._parola_listele, 
                                           fg_color="#4682B4")
        self.filter_button.grid(row=0, column=4, padx=5)
        
        # Parola Listesi
        self.liste_frame = ctk.CTkScrollableFrame(self, height=400)
        self.liste_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        
        # Alt Kontrol Paneli
        alt_kontrol_frame = ctk.CTkFrame(self)
        alt_kontrol_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        
        self.show_hide_button = ctk.CTkButton(alt_kontrol_frame, text=lang["show_hide_button"], command=self._parola_goster_gizle, 
                                              fg_color="#9C27B0")
        self.show_hide_button.pack(side="left", padx=5)
        self.copy_button = ctk.CTkButton(alt_kontrol_frame, text=lang["copy_button"], command=self._parola_kopyala, 
                                         fg_color="#FF9800")
        self.copy_button.pack(side="left", padx=5)
        self.delete_button = ctk.CTkButton(alt_kontrol_frame, text=lang["delete_button"], command=self._parola_sil, 
                                           fg_color="#FF4500")
        self.delete_button.pack(side="left", padx=5)
        self.backup_button = ctk.CTkButton(alt_kontrol_frame, text=lang["backup_button"], command=self._yedekle, 
                                           fg_color="#4CAF50")
        self.backup_button.pack(side="left", padx=5)
        self.exit_button = ctk.CTkButton(alt_kontrol_frame, text=lang["exit_button"], command=self.destroy, 
                                         fg_color="#757575")
        self.exit_button.pack(side="right", padx=5)
        
        self._parola_listele()

    def _parola_kaydet(self):
        try:
            lang = LANGUAGE_DICT[self.current_language]
            kategori = self.kategori_secim.get()
            aciklama = self.aciklama_girdi.get()
            uzunluk = int(self.uzunluk_girdi.get() or MIN_PAROLA_UZUNLUK)
            parola = self.logic.parola_uret(uzunluk)
            guc = self.logic.parola_guc_analizi(parola)
            self.logic.parola_kaydet(kategori, aciklama, parola, self.user_id)
            messagebox.showinfo(lang["success_message"], f"{aciklama}{lang['password_saved']}{guc}")
            self._parola_listele()
        except Exception as e:
            logging.error(f"Password save error: {str(e)}")
            messagebox.showerror(lang["error_message"], f"{lang['password_save_error']}{str(e)}")

    def _parola_listele(self):
        for widget in self.liste_frame.winfo_children():
            widget.destroy()
        
        lang = LANGUAGE_DICT[self.current_language]
        parolalar = self.logic.parola_listele(self.user_id)
        filtre = self.filtre_secim.get()
        arama = self.arama_girdi.get().lower()
        
        for password_id, kategori, aciklama, parola, tarih in parolalar:
            if (filtre != lang["categories"][0] and kategori != filtre) or \
               (arama and arama not in aciklama.lower()):
                continue
                
            frame = ctk.CTkFrame(self.liste_frame)
            frame.pack(fill="x", pady=2)
            
            text = f"[{kategori}] {aciklama}: {'*'*8 if not self.parolalar_goster else parola}"
            if self.logic.parola_suresi_kontrol(tarih):
                text += " ⏳"
                
            lbl = ctk.CTkLabel(frame, text=text)
            lbl.pack(side="left", padx=5)
            
            btn = ctk.CTkButton(frame, text="Seç" if self.current_language == "tr" else "Select", width=50, 
                               command=lambda pid=password_id: self._secim_yap(pid))
            btn.pack(side="right", padx=5)

    def _secim_yap(self, password_id):
        self.secili_password_id = password_id

    def _parola_sil(self):
        lang = LANGUAGE_DICT[self.current_language]
        if self.secili_password_id:
            if self.logic.parola_sil(self.secili_password_id):
                messagebox.showinfo(lang["success_message"], lang["password_deleted"])
                self._parola_listele()
            else:
                messagebox.showerror(lang["error_message"], "Deletion failed!")
        else:
            messagebox.showerror(lang["error_message"], lang["select_password"])

    def _parola_kopyala(self):
        lang = LANGUAGE_DICT[self.current_language]
        if self.secili_password_id:
            for p in self.logic.parola_listele(self.user_id):
                if p[0] == self.secili_password_id:
                    pyperclip.copy(p[3])
                    messagebox.showinfo(lang["success_message"], lang["password_copied"])
                    return
            messagebox.showerror(lang["error_message"], lang["password_not_found"])
        else:
            messagebox.showerror(lang["error_message"], lang["select_password"])

    def _parola_goster_gizle(self):
        self.parolalar_goster = not self.parolalar_goster
        self._parola_listele()

    def _yedekle(self):
        try:
            lang = LANGUAGE_DICT[self.current_language]
            yedek_dosya = self.logic.yedekle()
            messagebox.showinfo(lang["success_message"], f"{lang['backup_created']}{yedek_dosya}")
        except Exception as e:
            logging.error(f"Backup error: {str(e)}")
            messagebox.showerror(lang["error_message"], f"{lang['backup_error']}{str(e)}")

if __name__ == "__main__":
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")
    app = ParolaYoneticisi()
    app.mainloop()