
# hider

Çok platformlu otomatik IP değiştirici. İşletim sistemini otomatik algılar, uygun
backend'i seçer, belirlediğin aralıkta IP'ni değiştirir. Tor, anonsurf veya kendi
proxy listenden birini kullanır.

> [!WARNING]
> **Eğitim ve gizlilik koruma amaçlıdır.** Hider, ağ gizliliği ve proxy/Tor davranışlarını kontrollü ortamda öğrenmek için hazırlanmış bir projedir. Yalnızca kendi cihazlarında ve kullanımına izin verilen ağlarda kullan. IP değiştirmek anonimlik veya tam koruma garantisi vermez; erişim kontrollerini aşmak ya da yasa dışı faaliyeti gizlemek için kullanma. Bu açıklama tek başına hukuki sorumluluktan muafiyet sağlamaz.

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)


## ✨ Özellikler

- 🖥️ **Otomatik OS algılama** — Debian/Kali/Ubuntu, Arch/CachyOS/Manjaro/EndeavourOS,
  Fedora, openSUSE, macOS, Windows
- 🔀 **3 backend**:
  - **anonsurf** — Kali/Debian için Tor transparent proxy
  - **Tor** — SOCKS5 + ControlPort ile NEWNYM sinyali (tüm Linux + macOS)
  - **Proxy** — Kendi proxy listenden rastgele seçim (her OS)
- ⚡ **Otomatik Tor kurulumu** — Tor kurulu değilse indirir, `torrc`'yi yapılandırır,
  systemd servisini başlatır
- 🔍 **PySocks otomatik kurulumu** — SOCKS proxy desteği için gerekli modülü kurar
- ⏱️ **Sabit veya rastgele** IP değiştirme aralığı
- ✅ **IP doğrulama** — Değişmediyse 5 kez tekrar dener
- 📍 **Konum + ISP bilgisi** (ipinfo.io üzerinden)
- 📝 **Dosyaya loglama** (`hider.log`)
- 🛡️ **MAC whitelist** desteği
- 🧹 **Temiz çıkış** — `Ctrl+C`'de Tor servisini kapatır, sistemde sızıntı bırakmaz
- 🔐 **Root otomatik** — `sudo` olmadan çalıştırırsan kendini `sudo` ile yeniden başlatır


## 📦 Kurulum

### Gereksinimler

- **Linux / macOS / Windows**
- **Python 3.8+**
- `requests` modülü (`pip install requests`)
- `PySocks` modülü (SOCKS proxy için, tool otomatik kurar)

### Hızlı Kurulum

```bash
git clone https://github.com/kaandgnsh/hider.git
cd hider
chmod +x hider.py
```

Bağımlılıkları yükle:

```bash
# Debian/Kali/Ubuntu
sudo apt install python3-requests python3-socks

# Arch/CachyOS/Manjaro
sudo pacman -S python-requests python-pysocks

# Fedora
sudo dnf install python3-requests python3-pysocks

# macOS
pip3 install requests PySocks
```

### installer.sh ile Otomatik Kurulum

```bash
chmod +x installer.sh
sudo ./installer.sh
```

Script OS'ni algılar, `requests`/`PySocks`'u kurar, Tor'u kurar, anonsurf'u
(Kali'deyse) derler.

---

## 🚀 Kullanım

### Temel Kullanım

```bash
# Sabit 30 saniye aralıkla IP değiştir
sudo python3 hider.py -t 30

# Rastgele 20-90 saniye arasında değiştir
sudo python3 hider.py -r --min-wait 20 --max-wait 90

# Kendi proxy listenden kullan
sudo python3 hider.py -p ~/listeler/proxyler.txt -t 45

# Tor backend'ini zorla
sudo python3 hider.py -b tor -t 30

# anonsurf backend'ini zorla (Kali/Debian)
sudo python3 hider.py -b anonsurf -t 30

# Tek IP değişimi yap ve çık
sudo python3 hider.py --once

# Ayrıntılı log
sudo python3 hider.py -t 30 -v
```

### Root Kullanmadan (Sadece Proxy Backend)

```bash
python3 hider.py --no-sudo -p ~/listem.txt -t 30
```

---

## ⚙️ CLI Seçenekleri

| Seçenek | Açıklama |
|---------|----------|
| `-t`, `--time` | Sabit saniye aralığı (örn: 30) |
| `-r`, `--random` | Rastgele aralık modu |
| `--min-wait` | Rastgele modda minimum saniye (varsayılan 15) |
| `--max-wait` | Rastgele modda maksimum saniye (varsayılan 60) |
| `-p`, `--proxy-file` | Proxy listesi dosyası yolu |
| `-b`, `--backend` | `auto` / `anonsurf` / `tor` / `proxy` |
| `--tor-password` | Tor ControlPort şifresi (varsa) |
| `--once` | Tek IP değişimi yap ve çık |
| `--no-stop` | Çıkışta backend durdurulmasın |
| `--no-install` | Backend yoksa otomatik kurma |
| `--no-sudo` | Root değilse sudo ile yeniden başlatma |
| `-v`, `--verbose` | Ayrıntılı debug log |

---

## 🖥️ OS Bazlı Davranış

| OS Ailesi | Öncelikli Backend | Notlar |
|-----------|-------------------|--------|
| **Debian / Kali / Ubuntu** | `anonsurf` → `tor` → `proxy` | anonsurf varsa onu kullanır |
| **Arch / CachyOS / Manjaro** | `tor` → `anonsurf` → `proxy` | Tor otomatik kurulur |
| **Fedora / RHEL** | `tor` → `anonsurf` → `proxy` | Tor otomatik kurulur |
| **openSUSE** | `tor` → `anonsurf` → `proxy` | Tor otomatik kurulur |
| **macOS** | `proxy` → `tor` | Homebrew ile Tor kurulabilir |
| **Windows** | `proxy` → `tor` | Proxy dosyası önerilir |

---

## 🌐 Backend'ler

### 1. anonsurf (Kali/Debian)

Tor transparent proxy üzerinden tüm sistem trafiğini yönlendirir.

```bash
sudo python3 hider.py -b anonsurf -t 30
```

**Gereksinimler:**
- `anonsurf` kurulu olmalı (Kali'de varsayılan)
- `sudo apt install anonsurf`

### 2. Tor (Tüm Linux + macOS)

Tor SOCKS5 (port 9050) ve ControlPort (port 9051) üzerinden çalışır.

```bash
sudo python3 hider.py -b tor -t 30
```

**Gereksinimler:**
- `tor` kurulu olmalı (tool otomatik kurar)
- `torrc`'de `ControlPort 9051` ve `CookieAuthentication 0` açık olmalı
  (tool otomatik ekler)
- `PySocks` modülü (tool otomatik kurar)

**Manuel kontrol:**
```bash
sudo systemctl status tor
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org/
```

### 3. Proxy (Her OS)

Kendi proxy listenden rastgele seçim yapar.

```bash
sudo python3 hider.py -p ~/listem.txt -t 45
```

**Desteklenen proxy formatları:**

```
# Yorum satırı (atlanır)
http://user:pass@1.2.3.4:8080
https://5.6.7.8:8443
socks4://9.10.11.12:1080
socks5://13.14.15.16:1080
17.18.19.20:3128
21.22.23.24:8080:kullanici:sifre
```

Boş satırlar ve `#` ile başlayan satırlar atlanır. Her satır bir proxy'dir.

---

## 🔧 systemd Servisi

Tool'u arka planda çalıştırmak ve sistem açılışında başlatmak için:

```bash
sudo cp hider.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hider.service
```

**Durum ve log:**

```bash
sudo systemctl status hider
sudo journalctl -u hider -f
```

**Durdurma ve kaldırma:**

```bash
sudo systemctl stop hider
sudo systemctl disable --now hider
sudo rm /etc/systemd/system/hider.service
```

`hider.service` içindeki `ExecStart` satırını düzenleyerek parametreleri
değiştirebilirsin:

```ini
ExecStart=/usr/bin/python3 /opt/hider/hider.py -t 45
```

---

## 📁 Proxy Dosyası

`-p` / `--proxy-file` ile istediğin yoldaki dosyayı gösterebilirsin:

```bash
sudo python3 hider.py -p ~/listeler/proxyler.txt -t 30
sudo python3 hider.py -p /mnt/usb/proxyler.txt -t 45
sudo python3 hider.py -p /etc/hider/proxies.conf -t 60
```

`~` (ev dizini) ve göreli yollar desteklenir. Dosya yoksa veya içinde geçerli
proxy yoksa tool net hata verir.

---

## 📊 Örnek Çıktı

```
  _     _     _
 | |__ (_) __| | ___ _ __
 | '_ \| |/ _` |/ _ \ '__|
 | | | | | (_| |  __/ |
 |_| |_|_|\__,_|\___|_|

Author:    Kaan DOĞAN
GitHub:    https://github.com/kaandgnsh/hider
LinkedIn:  https://www.linkedin.com/in/kaan-do%C4%9Fan-911663280/
Instagram: @kaandgn.sh

OS      : arch / cachyos
Backend : Tor SOCKS5 (127.0.0.1:9050 -> ControlPort 9051)
Yetki   : root
PySocks : var

!! ONEMLI !! hider calisirken terminali kapatmayin.
Mod: Sabit 30s

Mevcut IP: 88.xx.xx.xx  (Istanbul, TR, Turk Telekom)
Yeni IP  : 192.42.116.142  (Frankfurt, DE, Tor Exit)

[~] Sonraki degisim: 30.0s sonra...
[OK] IP degisti
  Eski: 192.42.116.142
  Yeni: 185.220.101.5  (Amsterdam, NL, Tor Exit)
```

---

## 🔍 Sorun Giderme

### Tor başlamıyor

```bash
sudo systemctl status tor
sudo journalctl -u tor -n 50
```

Sorunlar:
- **ControlPort kapalı** → `/etc/tor/torrc` dosyasına `ControlPort 9051` ekle
- **Firewall engelliyor** → `sudo ufw allow 9050/tcp` ve `9051/tcp`
- **ISP Tor'u engelliyor** → `Bridge` kullan, `torrc`'ye bridge satırları ekle

### PySocks hatası

```
ModuleNotFoundError: No module named 'socks'
```

Çözüm:
```bash
sudo pacman -S python-pysocks      # Arch
sudo apt install python3-socks      # Debian
pip3 install PySocks                # Diğer
```

### IP değişmiyor

- Tor devresi kurulmamış olabilir, 60 saniye bekle
- `curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org/` ile test et
- Farklı çıkış düğümü için `SIGNAL NEWNYM` sonrası 3-5 saniye bekle

### "Uygun backend yok" hatası

```bash
# Tor kur
sudo pacman -S tor python-pysocks       # Arch
sudo apt install tor python3-socks      # Debian

# Veya proxy listesi ver
sudo python3 hider.py -p ~/listem.txt -t 30
```

---

## 🏗️ Proje Yapısı

```
hider/
├── hider.py           # Ana uygulama
├── installer.sh       # OS algılamalı kurulum scripti
├── hider.service      # systemd servis dosyası
├── README.md          # Bu dosya
└── hider.log          # Çalışma zamanı log dosyası (otomatik)
```

---

## 🤝 Katkı

Pull request'ler memnuniyetle karşılanır. Büyük değişiklikler için önce bir
issue açıp ne yapmak istediğini belirt.

1. Fork'la (`https://github.com/kaandgnsh/hider/fork`)
2. Feature branch oluştur (`git checkout -b ozellik/yeni-ozellik`)
3. Değişiklikleri commit'le (`git commit -am 'Yeni özellik ekle'`)
4. Branch'i push'la (`git push origin ozellik/yeni-ozellik`)
5. Pull request aç

---

## ⚠️ Eğitim Amacı ve Yasal Uyarı

Bu proje **eğitim, ağ gizliliğini anlama ve izinli güvenlik testleri** için hazırlanmıştır. Yalnızca kendi cihazlarında, laboratuvar ortamında veya açıkça izin aldığın sistemlerde kullan.

Tor veya proxy kullanmak seni otomatik olarak anonim yapmaz ve yaptığın işlemlerin yasal olduğu anlamına gelmez. Başkalarının sistemlerine izinsiz erişmek, güvenlik önlemlerini aşmak veya yasa dışı faaliyeti gizlemek amacıyla kullanma. Kullanıcı, yürürlükteki mevzuata ve hizmet koşullarına uymaktan sorumludur; eğitim amaçlı ibaresi tek başına hukuki sorumluluktan muafiyet sağlamaz.

---

## 📜 Lisans

MIT License — Detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 👤 Yazar

**Kaan DOĞAN**

- GitHub: [@kaandgnsh](https://github.com/kaandgnsh)
- LinkedIn: [Kaan DOĞAN](https://www.linkedin.com/in/kaan-do%C4%9Fan-911663280/)
- Instagram: [@kaandgn.sh](https://instagram.com/kaandgn.sh)

---

## 🌟 Teşekkür

- [Tor Project](https://www.torproject.org/)
- [anonsurf](https://github.com/Und3rf10w/kali-anonsurf)
- [ipinfo.io](https://ipinfo.io/)
- [Requests](https://requests.readthedocs.io/)
```
