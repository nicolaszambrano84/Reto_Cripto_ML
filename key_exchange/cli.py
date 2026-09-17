import os
from .crypto_utils import xor_components, validate_cmac_kcv, generate_aes256_key, wrap_tr31, unwrap_tr31, calculate_cmac_kcv
from .bonus import run_bonus_dukpt

def get_value(arg: str) -> str:
    if os.path.exists(arg):
        with open(arg, 'r') as f:
            return f.read().strip()
    return arg.strip()

def run_export_pek(args):
    comp1 = get_value(args.kek_component_1)
    comp2 = get_value(args.kek_component_2)
    
    # 1. Recombinar con XOR y validar la KEK
    kek = xor_components(comp1, comp2)
    validate_cmac_kcv(kek, args.kek_kcv)
    print(f"[+] KEK validada exitosamente contra el KCV: {args.kek_kcv}")
    
    # 2. Generar una PEK (AES-256)
    pek = generate_aes256_key()
    pek_kcv = calculate_cmac_kcv(pek)
    
    # Envolver la PEK en Key Block TR-31
    tr31_block = wrap_tr31(pek, kek, usage='P')
    
    with open(args.out, 'w') as f:
        f.write(tr31_block)
        
    print(f"[+] PEK generada y envuelta con exito.")
    print(f"    - Criptograma TR-31 guardado en: {args.out}")
    print(f"    - KCV de la PEK (para enviar a la contraparte): {pek_kcv}")

def run_import_bdk(args):
    comp1 = get_value(args.kek_component_1)
    comp2 = get_value(args.kek_component_2)
    
    # Validar la KEK
    kek = xor_components(comp1, comp2)
    validate_cmac_kcv(kek, args.kek_kcv)
    print(f"[+] KEK validada exitosamente contra el KCV: {args.kek_kcv}")
    
    tr31_data = get_value(args.bdk_keyblock)
    
    # 3. Desenvolver el key block de la BDK
    bdk = unwrap_tr31(tr31_data, kek)
    
    # Validar la BDK
    validate_cmac_kcv(bdk, args.bdk_kcv)
    print(f"[+] BDK desenrollada y validada correctamente contra el KCV: {args.bdk_kcv}")
    print(f"    - BDK (Hexadecimal): {bdk.hex().upper()}")
    
    # Ejecutar seccion Bonus opcional
    try:
        run_bonus_dukpt(bdk)
    except Exception as exc:
        print(f"\n[-] BONUS DUKPT no pudo ejecutarse: {exc}")
