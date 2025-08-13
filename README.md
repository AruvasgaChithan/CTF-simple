# 🕵️‍♂ Vulnerable Web CTF — Docker Edition

A collection of intentionally vulnerable web challenges for practicing ethical hacking and penetration testing skills.  
**Disclaimer:** This project is for **educational purposes only**. Do not expose it to the public internet.

---

## 📦 Setup Instructions

### **Prerequisites**
- [Docker](https://docs.docker.com/get-docker/) installed
- At least **2 GB RAM** and **2 GB free disk space**
- Internet connection for pulling base images

### **Build the Docker Image**
```bash
# Clone the repository
git clone https://github.com/AruvasgaChithan/CTF-simple.git
cd vuln_web

# Build the Docker image (no cache)
docker build --no-cache -t vuln_web .

Run the CTF Container
docker run -p 80:80 vuln_web
Access the CTF:
Open your browser and go to:
http://localhost:8080

