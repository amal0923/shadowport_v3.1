# ShadowPort v3.1

<p align="center">
   <img src="logo.png" width="700">
</p>

🔍 A powerful and lightweight cybersecurity tool for port scanning, service detection, and network reconnaissance. Built for security researchers and ethical hackers.
---

## 🔎 Description

ShadowPort v3.1 is an **all-in-one cybersecurity tool** for network reconnaissance and port scanning. It helps identify **live hosts, open ports, and running services** quickly and efficiently from your terminal.  
Designed for **red-teamers, cybersecurity students, and ethical hackers**, ShadowPort automates many common network scanning tasks and saves results in an organized format.  



<p align="center">
   <img src="shadowport.png" width="700">
</p>
---

## 🚀 Features

- ✅ Multi-target port scanning  
- ✅ Live host detection  
- ✅ Service and protocol enumeration  
- ✅ Save scan results to `.txt` files  
- ✅ Color-coded terminal output  
- ✅ Lightweight and fast  
- ✅ Compatible with most Linux distributions  

---

## 🛠️ Dependencies

Make sure these tools are installed on your system:  

- **Python 3** – `sudo apt install python3 python3-pip`  
- **Curl** – Usually pre-installed  
- **Nmap** – Optional for enhanced scanning (`sudo apt install nmap`)  

---

## 💻 Installation

Clone the repository:

```bash
git clone https://github.com/amal0923/shadowport_v3.1.git
cd shadowport_v3.1
```

Make the install script executable and run it:

```bash
chmod +x install.sh
sudo ./install.sh
```

Make the main script executable:

```bash
chmod +x shadowport_v3.py
```

```bash
sudo cp shadowport_v3.py /usr/bin/shadowport
```

---

## ▶️ Usage

Run the script with a target IP or domain:

```bash
shadowport_v3.py <target-ip->
```

Example:

```bash
shadowport_v3.py 192.168.1.10
```

The script will:  
1. Scan the target for **open ports**  
2. Detect **services running**  
3. Save results to `target_ip_scan_results.txt`  

---

## 🛡️ Example Output

```
🎯 Scan results for 192.168.1.10
---------------------------------
Open Ports:
22/tcp  - SSH
80/tcp  - HTTP
443/tcp - HTTPS
---------------------------------
✅ Results saved in 192.168.1.10_scan_results.txt
```

---

## 📁 Project Structure

```
shadowport_v3.1
 ├── install.sh         # Script to install dependencies
 ├── shadowport_v3.py   # Main scanner script
 └── shadowport.png     # Project preview image
```

---

## ⚠️ Disclaimer

⚠️ **For educational purposes only!**  
Do **not scan systems without explicit permission**.  
Unauthorized scanning may be illegal.  

---

## 🤝 Contributing

Contributions, feature suggestions, and bug reports are welcome!  
- Fork the repo  
- Make your changes  
- Submit a Pull Request  

Contact me via [LinkedIn](https://www.linkedin.com/in/amal-raj-k-a066b6375/) for collaborations.  

---

## ⭐ Star the Repository

If you find ShadowPort v3.1 useful, please **⭐ star the repository** to support development.  

🦾 **Unleash ShadowPort, secure networks ethically, and explore responsibly!**
