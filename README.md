# 🔥 HackingTool en Termux

HackingTool es un framework de hacking que recopila y organiza diferentes herramientas de seguridad y pruebas de penetración.  
Esta guía está adaptada específicamente para **Termux en Android**, eliminando pasos innecesarios como `sudo`.

---

## 🚀 Requisitos Previos

Antes de comenzar asegúrate de tener:

- Termux instalado desde F-Droid o GitHub (no Play Store).  
- Conexión a internet estable.  
- Espacio suficiente (mínimo 500MB).  

---

## ⚙️ Instalación

Ejecuta los siguientes comandos en tu Termux:

```bash
pkg update -y && pkg upgrade -y
pkg install -y git python python-pip bash
git clone https://github.com/TakizawaXD/WIfi.git
chmod -R 755 hackingtool
cd hackingtool
pip install -r requirements.txt
bash install.sh
