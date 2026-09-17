# MercadoPago Key Exchange Challenge

## Descripción
Este proyecto resuelve el desafío técnico de Seguridad Informática, implementando el intercambio de llaves TR-31 y KEK bajo lineamientos PCI PIN.

## Requisitos
Instalar dependencias:
```bash
pip install -r requirements.txt
```

## Ejecución
**Abrir la interfaz gráfica paso a paso:**
```bash
python -m key_exchange
```

La interfaz contiene dos módulos:
- **Exportar PEK:** recombina y valida la KEK, genera la PEK AES-256 y crea el bloque TR-31.
- **Importar BDK:** valida la KEK, desenvuelve y valida la BDK, y ejecuta el bonus DUKPT.

Cada módulo muestra visualmente el resultado de cada etapa. Los valores de ejemplo del reto se cargan automáticamente y pueden editarse antes de ejecutar el flujo.

Los comandos CLI anteriores siguen disponibles para ejecución automatizada:

**Generar PEK:**
```bash
python -m key_exchange export-pek --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 --kek-kcv F74B90 --out pek_tr31.txt
```

**Importar BDK:**
```bash
python -m key_exchange import-bdk --kek-component-1 db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6 --kek-component-2 1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7 --kek-kcv F74B90 --bdk-keyblock D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76 --bdk-kcv EABBDC
```
