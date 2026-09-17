import argparse
import sys
from .cli import run_export_pek, run_import_bdk

def main():
    if len(sys.argv) == 1:
        from .gui import run_gui
        run_gui()
        return

    parser = argparse.ArgumentParser(prog="python -m key_exchange", description="MercadoPago TR-31 Key Exchange Challenge")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Comando export-pek
    export_parser = subparsers.add_parser("export-pek")
    export_parser.add_argument("--kek-component-1", required=True, help="Ruta o valor componente 1")
    export_parser.add_argument("--kek-component-2", required=True, help="Ruta o valor componente 2")
    export_parser.add_argument("--kek-kcv", required=True, help="KCV esperado KEK")
    export_parser.add_argument("--out", required=True, help="Archivo salida del key block TR-31 de la PEK")
    
    # Comando import-bdk
    import_parser = subparsers.add_parser("import-bdk")
    import_parser.add_argument("--kek-component-1", required=True, help="Ruta o valor componente 1")
    import_parser.add_argument("--kek-component-2", required=True, help="Ruta o valor componente 2")
    import_parser.add_argument("--kek-kcv", required=True, help="KCV esperado KEK")
    import_parser.add_argument("--bdk-keyblock", required=True, help="Ruta o valor del key block BDK")
    import_parser.add_argument("--bdk-kcv", required=True, help="KCV esperado BDK")
    
    args = parser.parse_args()
    
    if args.command == "export-pek":
        run_export_pek(args)
    elif args.command == "import-bdk":
        run_import_bdk(args)

if __name__ == "__main__":
    main()
