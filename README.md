-------------------------------
HERRAMIENTA FORENSE PORTABLE
-------------------------------
Autor: Fernando Fernández Aguiló
TFM - Máster en Ciberseguridad (UGR)
Versión: 3.0

-------------------------------
📌 DESCRIPCIÓN
-------------------------------
Esta herramienta permite realizar un análisis forense básico de sistemas Windows, incluyendo:

- Adquisición de memoria RAM.
- Análisis de procesos y artefactos mediante Volatility 3.
- Extracción de cadenas y procesos sospechosos.
- Generación de informes automáticos (PDF, HTML, JSON, CSV).

-------------------------------
💾 PREPARACIÓN
-------------------------------
- Esta herramienta está diseñada para ejecutarse directamente desde este USB.
- Si la has descargado desde Google Drive o GitHub, extrae todos los archivos manteniendo la estructura de carpetas.

-------------------------------
⚙️ USO
-------------------------------
1. Ejecuta como administrador el archivo:

   👉 `main.exe` desde la terminal de python de winPython (o `main.py` si tienes Python instalado)

2. Sigue el menú interactivo:
   - Opción 1: Adquirir memoria.
   - Opción 2: Analizar la evidencia.
   - Opción 3: Generar informe.

3. Los resultados se guardarán en las carpetas:
   - `evidences/` → volcados y artefactos.
   - `report/`    → informes generados.

-------------------------------
🛠 DEPENDENCIAS
-------------------------------
- Si usas el script `main.py`, necesitas:
  - Python 3.8 o superior (o winPython si quieres un entorno virtual).
  - FTK Imager (la versión portable)
  - Volatility 3 (la versión portable)
  - Librerías: `fpdf`, `subprocess`, `hashlib`, etc.

-------------------------------
🌐 FUENTES Y ENLACES
-------------------------------
Descarga directa:
📦 https://drive.google.com/file/d/1zLS_elemSySg5__BRDBiQdE9fVxC5iFD/view?usp=sharing

-------------------------------
