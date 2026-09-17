import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .bonus import decrypt_bonus_dukpt
from .crypto_utils import (
    calculate_cmac_kcv,
    generate_aes256_key,
    unwrap_tr31,
    validate_cmac_kcv,
    wrap_tr31,
    xor_components,
)


COMPONENT_1 = "db375bb9dce3b14947e04e92a9356ebbb6e456f3518aed92c8dbc891f22f55d6"
COMPONENT_2 = "1e924acdb5442d3000c0fc9b20101aff1bd7a9bc27d36888c50cef64a7c818b7"
KEK_KCV = "F74B90"
BDK_KEYBLOCK = "D0112B0TX00E000080BF1D76A239777F8C2B605EB4FCF6DC9B9CFC6A5170C18282BDAB7D4D4D4559BC6A952101BA74EF8C1563BC2A73BF76"
BDK_KCV = "EABBDC"


class StepCard(ttk.LabelFrame):
    def __init__(self, parent, number, title):
        super().__init__(parent, text=f"  {number}. {title}  ", padding=(12, 8))
        self.status = ttk.Label(self, text="Pendiente", style="StepPending.TLabel")
        self.status.grid(row=0, column=0, sticky="w")
        self.value = ttk.Label(self, text="", style="Value.TLabel", wraplength=680)
        self.value.grid(row=1, column=0, sticky="w", pady=(5, 0))

    def complete(self, value):
        self.status.configure(text="Completado", style="StepDone.TLabel")
        self.value.configure(text=value)

    def fail(self, error):
        self.status.configure(text="Error", style="StepError.TLabel")
        self.value.configure(text=str(error))

    def reset(self):
        self.status.configure(text="Pendiente", style="StepPending.TLabel")
        self.value.configure(text="")


class FlowPanel(ttk.Frame):
    def __init__(self, parent, title, description):
        super().__init__(parent, padding=18)
        ttk.Label(self, text=title, style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(self, text=description, style="Muted.TLabel", wraplength=760).pack(anchor="w", pady=(3, 14))
        self.scroll_canvas = tk.Canvas(self, background="#f4f6f8", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.scroll_canvas.yview)
        self.scroll_canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.scroll_canvas.pack(side="left", fill="both", expand=True)
        self.steps = ttk.Frame(self.scroll_canvas)
        self.scroll_window = self.scroll_canvas.create_window((0, 0), window=self.steps, anchor="nw")
        self.steps.bind("<Configure>", self._update_scroll_region)
        self.scroll_canvas.bind("<Configure>", self._resize_content)

    def _update_scroll_region(self, _event=None):
        self.scroll_canvas.configure(scrollregion=self.scroll_canvas.bbox("all"))

    def _resize_content(self, event):
        self.scroll_canvas.itemconfigure(self.scroll_window, width=event.width)

    def make_step(self, number, title):
        card = StepCard(self.steps, number, title)
        card.pack(fill="x", pady=(0, 8))
        return card

    def reset_steps(self):
        for child in self.steps.winfo_children():
            child.reset()


class KeyExchangeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mercado Pago | Key Exchange")
        self.geometry("940x760")
        self.minsize(820, 650)
        self._configure_styles()
        self._build_header()
        self._build_tabs()

    def _configure_styles(self):
        self.configure(bg="#f4f6f8")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background="#f4f6f8", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.configure("TFrame", background="#f4f6f8")
        style.configure("PanelTitle.TLabel", foreground="#102a43", font=("Segoe UI", 19, "bold"))
        style.configure("Muted.TLabel", foreground="#52606d", font=("Segoe UI", 10))
        style.configure("StepPending.TLabel", foreground="#829ab1", font=("Segoe UI", 9, "bold"))
        style.configure("StepDone.TLabel", foreground="#16794c", font=("Segoe UI", 9, "bold"))
        style.configure("StepError.TLabel", foreground="#b42318", font=("Segoe UI", 9, "bold"))
        style.configure("Value.TLabel", foreground="#243b53", font=("Consolas", 9))
        style.configure("TButton", padding=(12, 7), font=("Segoe UI", 9, "bold"))
        style.configure("TLabelFrame", background="#ffffff", bordercolor="#d9e2ec")
        style.configure("TLabelFrame.Label", background="#ffffff", foreground="#243b53", font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", padding=6)

    def _build_header(self):
        header = ttk.Frame(self, padding=(24, 20, 24, 12))
        header.pack(fill="x")
        ttk.Label(header, text="KEY EXCHANGE", foreground="#d64545", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(header, text="Intercambio seguro de llaves", foreground="#102a43", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(header, text="Cada módulo muestra el mismo flujo criptográfico paso a paso.", style="Muted.TLabel").pack(anchor="w", pady=(2, 0))

    def _build_tabs(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.export_tab = self._build_export_tab(notebook)
        self.import_tab = self._build_import_tab(notebook)
        notebook.add(self.export_tab, text="  Exportar PEK  ")
        notebook.add(self.import_tab, text="  Importar BDK  ")

    def _input_row(self, parent, label, variable, browse=False):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=22).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        if browse:
            ttk.Button(row, text="Abrir archivo", command=lambda: self._load_file(variable)).pack(side="left", padx=(8, 0))

    def _build_export_tab(self, parent):
        tab = ttk.Frame(parent)
        panel = FlowPanel(tab, "Exportar PEK", "Combina la KEK, valida su KCV, genera una PEK AES-256 y la envuelve en un bloque TR-31.")
        panel.pack(fill="both", expand=True)
        values = {
            "comp1": tk.StringVar(value=COMPONENT_1),
            "comp2": tk.StringVar(value=COMPONENT_2),
            "kcv": tk.StringVar(value=KEK_KCV),
            "out": tk.StringVar(value="pek_tr31.txt"),
        }
        inputs = ttk.LabelFrame(panel.steps, text="Datos de entrada", padding=10)
        inputs.pack(in_=panel.steps, fill="x", pady=(0, 14))
        self._input_row(inputs, "Componente KEK 1", values["comp1"])
        self._input_row(inputs, "Componente KEK 2", values["comp2"])
        self._input_row(inputs, "KCV esperado KEK", values["kcv"])
        self._input_row(inputs, "Archivo de salida", values["out"])
        button = ttk.Button(panel.steps, text="Ejecutar exportación paso a paso", command=lambda: self._run_export(panel, values))
        button.pack(anchor="w", pady=(0, 12))
        panel.export_steps = [panel.make_step(1, "Recombinar componentes y validar KEK"), panel.make_step(2, "Generar PEK AES-256"), panel.make_step(3, "Envolver PEK en TR-31")]
        return tab

    def _build_import_tab(self, parent):
        tab = ttk.Frame(parent)
        panel = FlowPanel(tab, "Importar BDK", "Valida la KEK, desenvuelve la BDK desde TR-31, valida su KCV y ejecuta el bonus DUKPT.")
        panel.pack(fill="both", expand=True)
        values = {
            "comp1": tk.StringVar(value=COMPONENT_1),
            "comp2": tk.StringVar(value=COMPONENT_2),
            "kek_kcv": tk.StringVar(value=KEK_KCV),
            "keyblock": tk.StringVar(value=BDK_KEYBLOCK),
            "bdk_kcv": tk.StringVar(value=BDK_KCV),
        }
        reference = ttk.LabelFrame(panel.steps, text="Valores de referencia del reto", padding=10)
        reference.pack(fill="x", pady=(0, 12))
        ttk.Label(
            reference,
            text=f"Key block BDK (uso B0): {BDK_KEYBLOCK}\nKCV esperado de la BDK: {BDK_KCV}",
            style="Value.TLabel",
            wraplength=800,
            justify="left",
        ).pack(anchor="w")
        inputs = ttk.LabelFrame(panel.steps, text="Datos de entrada", padding=10)
        inputs.pack(fill="x", pady=(0, 14))
        self._input_row(inputs, "Componente KEK 1", values["comp1"])
        self._input_row(inputs, "Componente KEK 2", values["comp2"])
        self._input_row(inputs, "KCV esperado KEK", values["kek_kcv"])
        self._input_row(inputs, "Key block BDK", values["keyblock"], browse=True)
        self._input_row(inputs, "KCV esperado BDK", values["bdk_kcv"])
        ttk.Button(panel.steps, text="Ejecutar importación paso a paso", command=lambda: self._run_import(panel, values)).pack(anchor="w", pady=(0, 12))
        panel.import_steps = [
            panel.make_step(1, "Recombinar componentes y validar KEK"),
            panel.make_step(2, "Desenvolver key block TR-31"),
            panel.make_step(3, "Validar KCV de la BDK"),
            panel.make_step(4, "Derivar clave DUKPT y descifrar mensaje"),
        ]
        return tab

    @staticmethod
    def _load_file(variable):
        path = filedialog.askopenfilename()
        if path:
            with open(path, "r", encoding="utf-8") as handle:
                variable.set(handle.read().strip())

    @staticmethod
    def _reset(panel, attribute):
        for step in getattr(panel, attribute):
            step.reset()

    def _run_export(self, panel, values):
        self._reset(panel, "export_steps")
        steps = panel.export_steps
        try:
            kek = xor_components(values["comp1"].get().strip(), values["comp2"].get().strip())
            validate_cmac_kcv(kek, values["kcv"].get().strip())
            steps[0].complete(f"KEK válida. KCV: {values['kcv'].get().strip().upper()}")

            pek = generate_aes256_key()
            pek_kcv = calculate_cmac_kcv(pek)
            steps[1].complete(f"PEK AES-256 generada. KCV: {pek_kcv}")

            tr31_block = wrap_tr31(pek, kek, usage="P")
            output_path = values["out"].get().strip() or "pek_tr31.txt"
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(tr31_block)
            steps[2].complete(f"TR-31 guardado en {os.path.abspath(output_path)}")
            messagebox.showinfo("Exportación completada", f"PEK envuelta correctamente.\nKCV de la PEK: {pek_kcv}")
        except Exception as exc:
            next_step = next((step for step in steps if step.status.cget("text") == "Pendiente"), steps[-1])
            next_step.fail(exc)
            messagebox.showerror("Error de exportación", str(exc))

    def _run_import(self, panel, values):
        self._reset(panel, "import_steps")
        steps = panel.import_steps
        try:
            kek = xor_components(values["comp1"].get().strip(), values["comp2"].get().strip())
            validate_cmac_kcv(kek, values["kek_kcv"].get().strip())
            steps[0].complete(f"KEK válida. KCV: {values['kek_kcv'].get().strip().upper()}")

            keyblock = values["keyblock"].get().strip()
            if keyblock.startswith("D0144P"):
                raise ValueError("El archivo cargado es una PEK (D0144P), no el key block BDK esperado (D0112B0T).")

            bdk = unwrap_tr31(keyblock, kek)
            steps[1].complete(f"BDK desenvuelta: {bdk.hex().upper()}")
            validate_cmac_kcv(bdk, values["bdk_kcv"].get().strip())
            steps[2].complete(f"BDK válida. KCV: {values['bdk_kcv'].get().strip().upper()}")

            dukpt_key, plaintext = decrypt_bonus_dukpt(bdk)
            steps[3].complete(f"Mensaje: {plaintext.rstrip(b'\x00').decode('utf-8')} | Clave derivada: {dukpt_key.hex().upper()}")
            messagebox.showinfo("Importación completada", "BDK validada y bonus DUKPT ejecutado correctamente.")
        except Exception as exc:
            next_step = next((step for step in steps if step.status.cget("text") == "Pendiente"), steps[-1])
            next_step.fail(exc)
            messagebox.showerror("Error de importación", str(exc))


def run_gui():
    app = KeyExchangeApp()
    app.mainloop()