# Trazado de Vulnerabilidad: CVE-2024-0204 en GoAnywhere MFT (Fortra)

![Licencia CC BY-NC-SA 4.0](https://licensebuttons.net/l/by-nc-sa/4.0/88x31.png)

**Actividad de la Unidad 2 – Puesta en Producción Segura**  
**Título de la actividad**: Trazado de una vulnerabilidad  
**Resultado de aprendizaje**: RA2 d – Conocer listas de amenazas y trazar vulnerabilidades en fuentes abiertas

## Descripción del Proyecto

Este repositorio/documento contiene el trazado completo de la vulnerabilidad **CVE-2024-0204**, una falla crítica de omisión de autenticación (authentication bypass) en el software **GoAnywhere MFT** de Fortra.

- **Tipo de vulnerabilidad**: Omisión de autenticación / Forced Browsing (CWE-425)  
- **CVSS**: 9.8 Crítico (vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
- **Impacto**: Un atacante remoto sin credenciales puede crear un usuario administrador directamente en el portal de administración, lo que permite takeover completo del sistema.  
- **Productos afectados**: GoAnywhere MFT versiones 6.0.1 a 7.4.1 (incluidas).  
- **Fecha de publicación del advisory**: Enero 2024 (parcheado en diciembre 2023 en v7.4.1).  
- **Historia**: Similar a CVE-2023-0669 (explotado masivamente por Cl0p en 2023), esta falla expone endpoints de setup inicial sin protección adecuada.

El trazado sigue el flujo recomendado en la actividad:  
INCIBE → Fabricante (Fortra) → CVE.org → NVD → CWE → CAPEC → Registro JSON.

## Objetivos Cumplidos

- Conocer y navegar por las principales listas y bases de datos de ciberseguridad:  
  - INCIBE (avisos nacionales)  
  - CVE (Common Vulnerabilities and Exposures)  
  - NVD (National Vulnerability Database – NIST)  
  - CWE (Common Weakness Enumeration)  
  - CAPEC (Common Attack Pattern Enumeration and Classification)  
  - CVSS (Common Vulnerability Scoring System)  

- Realizar un trazado detallado de la vulnerabilidad:  
  - Punto de partida → Información del fabricante → Detalles CVE/NVD → Criticidad CVSS → Debilidades CWE → Patrones de ataque CAPEC → Registro estructurado JSON.  

- Incluir capturas de pantalla, explicaciones y análisis de mitigaciones.

## Contenido del Repositorio

- `TrazadoVulnerabilidadGoAnywhere.md` → Documento principal con el trazado completo (texto + capturas).  
- `images/` → Carpeta con todas las capturas de pantalla referenciadas en el Markdown (img1.png, img2.png, ..., img16.png).  
- `README.md` → Este archivo (información general y cómo usar el trabajo).

## Cómo Usar / Ver el Trazado

1. Abre `TrazadoVulnerabilidadGoAnywhere.md` en un visor Markdown (Typora, VS Code, Obsidian, GitHub, etc.).  
2. Las imágenes se cargan automáticamente si están en la carpeta `images/`.  
3. Para exportar a PDF (modalidad presencial):  
   - Usa Typora → Exportar → PDF  
   - O Pandoc: `pandoc TrazadoVulnerabilidadGoAnywhere.md -o TrazadoVulnerabilidadGoAnywhere.pdf --pdf-engine=wkhtmltopdf`

## Enlaces Clave de Referencia

- Aviso INCIBE: https://www.incibe.es/empresas/avisos/vulnerabilidad-critica-de-omision-de-autenticacion-en-goanywhere-mft-de-fortra  
- Advisory Fortra (FI-2024-001): https://www.fortra.com/security/advisories/product-security/fi-2024-001  
- Registro CVE: https://www.cve.org/CVERecord?id=CVE-2024-0204  
- Detalle NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-0204  
- CWE-425: https://cwe.mitre.org/data/definitions/425.html  
- CAPEC-143 (principal relacionado): https://capec.mitre.org/data/definitions/143.html  

## Notas Adicionales

- **Fecha de realización**: Enero 2026 (basado en conocimiento actualizado).  
- **Autor**: Naiara (estudiante de Puesta en Producción Segura).  
- **Licencia**: CC BY-NC-SA 4.0 – Puedes compartir y adaptar con atribución, uso no comercial y misma licencia.  

Este trabajo demuestra la interconexión de las fuentes abiertas de ciberseguridad y cómo trazar una vulnerabilidad de principio a fin.

¡Gracias por revisar! Si es para la tarea de la Unidad 2, espero que te sirva de 10. 🚀