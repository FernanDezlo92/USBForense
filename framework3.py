import subprocess
import os
import sys
import json
import time
from datetime import datetime
import hashlib
import csv
import shutil
import re 
from fpdf import FPDF

if getattr(sys, 'frozen', False):
    #BASE_DIR = sys._MEIPASS
    BASE_DIR = os.path.dirname(sys.executable)
    EXE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    EXE_DIR = BASE_DIR

EVIDENCE_DIR = os.path.join(EXE_DIR, "evidences")
REPORT_DIR = os.path.join(EXE_DIR, "report")
os.environ["VOLATILITY_SYMBOL_PATHS"] = os.path.join(BASE_DIR, "volatility", "symbols")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.environ["PYTHONPATH"] = os.path.join(EXE_DIR, "Volatility")


def log(msg):
    print(f"[{datetime.now()}] {msg}")

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def wait_for_file(filepath, description):
    wait_time = 0
    while not os.path.exists(filepath):
        log(f"Esperando a que se cree el archivo de {description}...")
        time.sleep(5)
        wait_time += 5
        if wait_time > 300:
            log(f"ERROR: Timeout esperando el archivo de {description}.")
            sys.exit(1)

# === FUNCIONES DE ADQUISICIÓN ===

def run_ftk_image():
    output_img = os.path.join(EVIDENCE_DIR, "disco.img")
    ftk_path = os.path.join(BASE_DIR, "FTK Imager", "FTK Imager.exe")
    if not os.path.exists(ftk_path):
        log("ERROR: FTK Imager no encontrado.")
        return
    log("Iniciando adquisición de disco con FTK Imager...")
    cmd = fr'"{ftk_path}" --create_raw_image --source \\.\PhysicalDrive0 --destination "{output_img}"'
    subprocess.run(cmd, shell=True)
    log(f"Imagen creada: {output_img}")
    img_hash = hash_file(output_img)
    log(f"SHA256 de la imagen: {img_hash}")
    with open(os.path.join(REPORT_DIR, "hashes_adquisicion.txt"), "a") as f:
        f.write(f"{output_img}: {img_hash}\n")

def seleccionar_y_copiar_archivos():
    print("\nIntroduce la ruta absoluta de cada archivo o carpeta que deseas copiar.")
    print("Introduce una línea vacía para finalizar.\n")

    entradas = []
    while True:
        ruta = input("Ruta: ").strip()
        if ruta == "":
            break
        if not os.path.exists(ruta):
            print("Ruta no válida, intenta de nuevo.")
        else:
            entradas.append(ruta)

    if not entradas:
        print("No se han seleccionado rutas.")
        return

    log("Iniciando copia selectiva de archivos...")
    for entrada in entradas:
        nombre = os.path.basename(entrada)
        destino = os.path.join(EVIDENCE_DIR, nombre)
        try:
            if os.path.isfile(entrada):
                shutil.copy2(entrada, destino)
                log(f"Archivo copiado: {destino}")
                file_hash = hash_file(destino)
                log(f"SHA256: {file_hash}")
                with open(os.path.join(REPORT_DIR, "hashes_adquisicion.txt"), "a") as f:
                    f.write(f"{destino}: {file_hash}\n")
            elif os.path.isdir(entrada):
                shutil.copytree(entrada, destino)
                log(f"Carpeta copiada: {destino}")
                for root, dirs, files in os.walk(destino):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_hash = hash_file(file_path)
                        log(f"SHA256 de {file_path}: {file_hash}")
                        with open(os.path.join(REPORT_DIR, "hashes_adquisicion.txt"), "a") as f:
                            f.write(f"{file_path}: {file_hash}\n")
        except Exception as e:
            log(f"ERROR al copiar {entrada}: {e}")

def menu_adquisicion():
    print("\n========== ADQUISICIÓN DE EVIDENCIAS ==========")
    print("1. Imagen completa del disco (FTK Imager)")
    print("2. Solo archivos/carpetas seleccionadas")
    print("3. Solo análisis de memoria (WinPMEM + Volatility)")
    print("===============================================")
    choice = input("Selecciona una opción (1/2/3): ").strip()

    if choice == "1":
        run_ftk_image()
    elif choice == "2":
        seleccionar_y_copiar_archivos()
    elif choice == "3":
        log("Saltando a adquisición de memoria...")
    else:
        print("Opción no válida.")
        menu_adquisicion()


def run_winpmem():
    mem_dump = os.path.join(EVIDENCE_DIR, "memoria.raw")
    winpmem_path = os.path.join(BASE_DIR, "WinPmem", "winpmem_mini_x64_rc2.exe")
    if not os.path.exists(winpmem_path):
        log("ERROR: WinPMEM no encontrado.")
        sys.exit(1)
    log("Iniciando adquisición de RAM con WinPMEM...")
    cmd = f'"{winpmem_path}" "{mem_dump}"'
    log(f"Comando ejecutado: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        log("⚠️ WinPMEM terminó con código distinto de 0. Puede ser normal por la descarga del driver.")
    wait_for_file(mem_dump, "volcado de memoria")
    log(f"Volcado de memoria creado: {mem_dump}")
    return mem_dump

def dump_strings_con_resumen(mem_dump):
    log("🔍 Extrayendo cadenas (strings) del volcado de memoria...")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    strings_file = os.path.join(REPORT_DIR, f"strings_memoria_{timestamp}.txt")
    resumen_file = os.path.join(REPORT_DIR, f"resumen_strings_memoria_{timestamp}.txt")

    # Path portable a strings.exe
    strings_path = os.path.join(BASE_DIR, "tools", "strings64.exe")
    cmd_strings = f'"{strings_path}" -a -n 6 "{mem_dump}" > "{strings_file}"'
    result = subprocess.run(cmd_strings, shell=True)

    if result.returncode != 0:
        log("⚠️ Error al ejecutar strings sobre el volcado de memoria.")
        return

    log(f"📄 Strings extraídas y guardadas en: {strings_file}")

    # Patrones
    patrones = {
        "URLs": r"http[s]?://\S+",
        "IPs": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "Passwords": r"(?i)password|passwd|pwd|contraseña|clave",
        "Admin": r"(?i)admin|administrator|root",
        "PowerShell / cmd": r"(?i)powershell|cmd\.exe|whoami|net user|tasklist|wmic|Get-"
    }

    # Leemos strings
    with open(strings_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    # Resumen en Python (sin grep)
    with open(resumen_file, "w", encoding="utf-8") as resumen:
        resumen.write(f"== RESUMEN STRINGS: {mem_dump} ==\n")
        resumen.write(f"Generado: {datetime.now()}\n\n")

        for descripcion, regex in patrones.items():
            resumen.write(f"--- {descripcion} ---\n")
            matches = set()

            for line in lines:
                if re.search(regex, line):
                    matches.add(line.strip())

            if matches:
                for match in sorted(matches):
                    resumen.write(match + "\n")
            else:
                resumen.write("[No encontrado]\n")

            resumen.write("\n")

    log(f"📄 Resumen de strings generado en: {resumen_file}")

def run_volatility3(mem_dump):
    vol_py = os.path.join(BASE_DIR, "Volatility", "vol.py")
    if not os.path.exists(vol_py):
        log("ERROR: vol.py de Volatility 3 no encontrado.")
        sys.exit(1)

    # windows.info
    log("Ejecutando Volatility 3 - windows.info ...")
    cmd_info = f'python "{vol_py}" -f "{mem_dump}" windows.info'
    info_result = subprocess.run(cmd_info, shell=True, capture_output=True, text=True)

    # windows.pslist
    log("Ejecutando Volatility 3 - windows.pslist ...")
    cmd_pslist = f'python "{vol_py}" -f "{mem_dump}" windows.pslist'
    pslist_result = subprocess.run(cmd_pslist, shell=True, capture_output=True, text=True)
    parsed_pslist = parse_pslist_output(pslist_result.stdout)

    # windows.netscan
    log("Ejecutando Volatility 3 - windows.netscan ...")
    cmd_netscan = f'python "{vol_py}" -f "{mem_dump}" windows.netscan'
    netscan_result = subprocess.run(cmd_netscan, shell=True, capture_output=True, text=True)

    # windows.logon
    log("Ejecutando Volatility 3 - windows.logon ...")
    cmd_logon = f'python "{vol_py}" -f "{mem_dump}" windows.logon'
    logon_result = subprocess.run(cmd_logon, shell=True, capture_output=True, text=True)

    # windows.registry.hivelist
    log("Ejecutando Volatility 3 - windows.registry.hivelist ...")
    cmd_hivelist = f'python "{vol_py}" -f "{mem_dump}" windows.registry.hivelist'
    hivelist_result = subprocess.run(cmd_hivelist, shell=True, capture_output=True, text=True)

    # Nuevo: windows.registry.sam
    log("Ejecutando Volatility 3 - windows.registry.sam ...")
    cmd_sam = f'python "{vol_py}" -f "{mem_dump}" windows.registry.sam'
    sam_result = subprocess.run(cmd_sam, shell=True, capture_output=True, text=True)

    # Nuevo: windows.getsids
    log("Ejecutando Volatility 3 - windows.getsids ...")
    cmd_sids = f'python "{vol_py}" -f "{mem_dump}" windows.getsids'
    sids_result = subprocess.run(cmd_sids, shell=True, capture_output=True, text=True)

    # windows.malware.suspicious_threads
    log("Ejecutando Volatility 3 - windows.malware.suspicious_threads ...")
    cmd_susp = f'python "{vol_py}" -f "{mem_dump}" windows.malware.suspicious_threads.SuspiciousThreads'
    susp_result = subprocess.run(cmd_susp, shell=True, capture_output=True, text=True)


    return {
        "info": info_result.stdout,
        "pslist_raw": pslist_result.stdout,
        "pslist_parsed": parsed_pslist,
        "netscan_raw": netscan_result.stdout,
        "sam_raw": sam_result.stdout,
        "sids_raw": sids_result.stdout,
        "suspicious_threads_raw": susp_result.stdout,
        "logon_raw": logon_result.stdout,
        "hivelist_raw": hivelist_result.stdout,
    }

def interactive_volatility(mem_dump):
    log("🧠 Modo interactivo Volatility iniciado. Escribe 'salir' para terminar.")
    log("⚠️ Volatility ejecutara por si solo 'windows.getsids','windows.registry.sam','windows.info', 'windows.netscan', 'windows.logon', 'windows.registry.hivelist' y 'windows.pslist'.")
    while True:
        plugin = input("\n🔍 Introduce el plugin de Volatility (ej: windows.pslist): ").strip()
        if plugin.lower() in ["salir", "exit", "quit"]:
            log("🚪 Saliendo del modo interactivo.")
            break

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_txt = os.path.join(REPORT_DIR, f"{plugin.replace('.', '_')}_{timestamp}.txt")
        output_html = os.path.join(REPORT_DIR, f"{plugin.replace('.', '_')}_{timestamp}.html")

        cmd = f'python "{vol_py}" -f "{mem_dump}" {plugin}'
        log(f"⏳ Ejecutando: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        with open(output_txt, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        log(f"📝 Resultado guardado en: {output_txt}")

        # Opcional: crear versión HTML
        with open(output_html, "w", encoding="utf-8") as f:
            f.write("<html><body><pre>")
            f.write(result.stdout.replace("<", "&lt;").replace(">", "&gt;"))
            f.write("</pre></body></html>")
        log(f"🌐 Versión HTML generada: {output_html}")

def parse_pslist_output(output):
    lines = output.strip().splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("PID"):
            headers = line.strip().split("\t")
            table_lines = lines[i+1:]
            break
    else:
        return []

    processes = []
    for line in table_lines:
        if line.strip() == "":
            continue
        values = line.strip().split("\t")
        if len(values) != len(headers):
            continue
        process = dict(zip(headers, values))
        processes.append(process)
    return processes

def detectar_procesos_sospechosos(lista_procesos):
    sospechosos = []
    nombres_maliciosos = ["mimikatz.exe", "meterpreter", "backdoor", "powershell.exe", "cmd.exe"]

    for proc in lista_procesos:
        motivos = []
        nombre = proc.get("ImageFileName", "").lower()
        pid = int(proc.get("PID", 0)) if proc.get("PID", "0").isdigit() else 0
        ppid = int(proc.get("PPID", 0)) if proc.get("PPID", "0").isdigit() else 0
        create_time = proc.get("CreateTime", "").lower()

        if nombre == "" or nombre == "n/a":
            motivos.append("Nombre vacío o no válido")
        if nombre in nombres_maliciosos:
            motivos.append(f"Nombre de proceso malicioso detectado: {nombre}")
        if ppid == 0 and pid != 4:
            motivos.append("Proceso sin padre válido (PPID = 0)")
        if "n/a" in create_time:
            motivos.append("Tiempo de creación no disponible")
        if pid > 100000 and ("powershell" in nombre or "cmd" in nombre or "unknown" in nombre):
            motivos.append("PID anormalmente alto")

        if motivos:
            sospechosos.append({
                "PID": pid,
                "ImageFileName": nombre,
                "RiesgoDetectado": motivos
            })

    return sospechosos

def generate_report(data, filename="reporte_completo"):
    report_file = os.path.join(REPORT_DIR, f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, "w") as f:
        json.dump(data, f, indent=4)
    log(f"✅ Reporte generado: {report_file}")
    return report_file

def generate_slim_report(total, sospechosos):
    resumen = {
        "resumen": {
            "total_procesos": total,
            "procesos_sospechosos": len(sospechosos)
        },
        "procesos_sospechosos": sospechosos,
        "timestamp": str(datetime.now())
    }
    generate_report(resumen, filename="reporte_slim")
    export_suspects_to_csv(sospechosos)
    export_suspects_to_html(sospechosos)

def export_suspects_to_csv(data):
    if not data:
        return
    csv_file = os.path.join(REPORT_DIR, f"procesos_sospechosos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    log(f"📄 CSV generado: {csv_file}")

def export_suspects_to_html(data):
    if not data:
        return
    html_file = os.path.join(REPORT_DIR, f"procesos_sospechosos_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Procesos Sospechosos</title></head><body>")
        f.write("<h2>Procesos Sospechosos</h2><table border='1'><tr>")
        for col in data[0].keys():
            f.write(f"<th>{col}</th>")
        f.write("</tr>")
        for row in data:
            f.write("<tr>")
            for val in row.values():
                f.write(f"<td>{val}</td>")
            f.write("</tr>")
        f.write("</table></body></html>")
    log(f"🌐 HTML generado: {html_file}")

def export_user_info_html(logon_output, hivelist_output):
    html_file = os.path.join(REPORT_DIR, f"informacion_usuarios_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Información de Usuarios</title></head><body>")
        f.write("<h2>Información relacionada con usuarios</h2>")
        f.write("<h3>Logon Sessions</h3><pre>")
        f.write(logon_output.replace("<", "&lt;").replace(">", "&gt;"))
        f.write("</pre><h3>Registry Hivelist</h3><pre>")
        f.write(hivelist_output.replace("<", "&lt;").replace(">", "&gt;"))
        f.write("</pre></body></html>")
    log(f"🧑‍💻 HTML de información de usuarios generado: {html_file}")

def export_user_info_html_2(data):
    html_file = os.path.join(REPORT_DIR, f"usuarios_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Información de Usuarios</title></head><body>")
        f.write("<h2>Información relacionada con usuarios</h2>")

        f.write("<h3>Usuarios del sistema (SAM)</h3><pre>")
        f.write(data.get("sam_raw", "No disponible"))
        f.write("</pre>")

        f.write("<h3>Identificadores SID (getsids)</h3><pre>")
        f.write(data.get("sids_raw", "No disponible"))
        f.write("</pre>")

        f.write("</body></html>")
    log(f"👤 HTML de usuarios generado: {html_file}")

def export_report_to_pdf(report_data, procesos_sospechosos, user_data):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Informe Forense", ln=True, align="C")
    
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Resumen de adquisición:", ln=True)
    
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, f"Memoria dump: {report_data.get('memory_dump', '')}")
    pdf.multi_cell(0, 10, f"Hash SHA-256: {report_data.get('memory_hash', '')}")
    
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Procesos sospechosos detectados:", ln=True)
    
    pdf.set_font("Arial", "", 12)
    if procesos_sospechosos:
        for proc in procesos_sospechosos:
            riesgos = ', '.join(proc['RiesgoDetectado'])
            pdf.multi_cell(0, 10, f"PID: {proc['PID']} - {proc['ImageFileName']} - Riesgo: {riesgos}")
    else:
        pdf.cell(0, 10, "No se detectaron procesos sospechosos.", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Análisis de hilos sospechosos:", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, user_data.get("suspicious_threads_raw", "No disponible"))

    pdf_file = os.path.join(REPORT_DIR, f"reporte_forense_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    pdf.output(pdf_file)
    log(f"📄 PDF generado: {pdf_file}")

# === MAIN ===
if __name__ == "__main__":
    log("===== INICIANDO PROCESO FORENSE =====")

    # Paso 1: Mostrar menú de adquisición
    menu_adquisicion()

    # Paso 2: Adquisición de memoria y Volatility 3
    mem_dump = run_winpmem()
    mem_hash = hash_file(mem_dump)
    dump_strings_con_resumen(mem_dump)
    interactive_volatility(mem_dump)
    volatility_data = run_volatility3(mem_dump)

    procesos_sospechosos = detectar_procesos_sospechosos(volatility_data["pslist_parsed"])

    report_data = {
        "memory_dump": mem_dump,
        "memory_hash": mem_hash,
        "volatility3_info": volatility_data["info"],
        "memory_pslist_raw": volatility_data["pslist_raw"],
        "memory_pslist_parsed": volatility_data["pslist_parsed"],
        "memory_netscan_raw": volatility_data["netscan_raw"],
        "procesos_sospechosos": procesos_sospechosos,
        "timestamp": str(datetime.now())
    }

    generate_report(report_data)
    generate_slim_report(len(volatility_data["pslist_parsed"]), procesos_sospechosos)
    export_user_info_html(volatility_data["logon_raw"], volatility_data["hivelist_raw"])
    export_user_info_html_2(volatility_data)
    export_report_to_pdf(report_data, procesos_sospechosos, volatility_data)

    log("===== PROCESO COMPLETADO =====")