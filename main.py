from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk, ImageOps, ImageEnhance
from fg_log_analyzer import FGLogAnalyzer

BASE_DIR = Path(__file__).resolve().parent
BACKGROUND_FILE = BASE_DIR / "assets" / "cyber_background.png"

COLORS = {
    "base": "#071c19",
    "panel": "#0b2825",
    "panel_alt": "#10342f",
    "input": "#153b36",
    "border": "#356a5c",
    "mint": "#b7d9c9",
    "bright": "#f1f4df",
    "muted": "#9cb9ab",
    "gold": "#c5aa73",
    "gold_hover": "#dfc38d",
    "teal": "#3c9f8b",
    "teal_hover": "#52b5a0",
    "danger": "#f0b37c",
}


class CyberLogApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberLog Analyzer | FG")
        self.root.geometry("1280x840")
        self.root.minsize(1050, 730)
        self.analyzer = FGLogAnalyzer()
        self.path_label = tk.StringVar(value="Nincs megnyitott fájl")
        self.summary = tk.StringVar(value="Tölts be egy CSV-fájlt, vagy használd a mintanaplót.")
        self.ip_filter = tk.StringVar()
        self.status_filter = tk.StringVar(value="Összes")
        self.threshold = tk.StringVar(value="5")
        self.window_seconds = tk.StringVar(value="60")
        self._background_image = Image.open(BACKGROUND_FILE).convert("RGB")
        self._background_render = None
        self._background_size = None
        self._background_job = None
        self.build_ui()
        self.load_file(BASE_DIR / "data" / "sample_log.csv")

    def _draw_background(self, event=None):
        if event is not None and event.widget is not self.root:
            return
        size = (max(self.root.winfo_width(), 1), max(self.root.winfo_height(), 1))
        if size == self._background_size or size[0] < 200 or size[1] < 200:
            return
        if self._background_job is not None:
            self.root.after_cancel(self._background_job)
        self._background_job = self.root.after(90, lambda: self._apply_background(size))

    def _apply_background(self, size):
        self._background_job = None
        if not self.root.winfo_exists():
            return
        actual = (self.root.winfo_width(), self.root.winfo_height())
        if actual != size:
            self._draw_background()
            return
        image = ImageOps.fit(self._background_image, size, method=Image.Resampling.LANCZOS, centering=(0.5, 0.37))
        image = ImageEnhance.Brightness(image).enhance(0.78)
        self._background_render = ImageTk.PhotoImage(image)
        self.background_label.configure(image=self._background_render)
        self._background_size = size

    def _button(self, parent, title, command, accent=False):
        style = "Accent.TButton" if accent else "TButton"
        return ttk.Button(parent, text=title, command=command, style=style)

    def _section_title(self, parent, title):
        label = tk.Label(parent, text=title, bg=COLORS["panel"], fg=COLORS["gold"],
                         font=("Segoe UI", 11, "bold"), anchor="w")
        label.pack(fill="x", pady=(0, 7))
        return label

    def build_ui(self):
        c = COLORS
        self.root.configure(bg=c["base"])
        self.background_label = tk.Label(self.root, bd=0, bg=c["base"], highlightthickness=0)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.background_label.lower()
        self.root.bind("<Configure>", self._draw_background)

        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background=c["panel"])
        style.configure("TLabel", background=c["panel"], foreground=c["bright"], font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(14, 9),
                        background=c["panel_alt"], foreground=c["mint"], bordercolor=c["border"],
                        lightcolor=c["border"], darkcolor=c["border"], relief="flat")
        style.map("TButton", background=[("active", c["teal"])],
                  foreground=[("active", "#ffffff")])
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10), padding=(18, 9),
                        background=c["gold"], foreground=c["base"], bordercolor=c["gold"], relief="flat")
        style.map("Accent.TButton", background=[("active", c["gold_hover"])],
                  foreground=[("active", c["base"])])
        style.configure("TEntry", fieldbackground=c["input"], foreground=c["bright"],
                        bordercolor=c["border"], padding=(7, 7), insertcolor=c["bright"])
        style.map("TEntry", fieldbackground=[("focus", c["input"])],
                  bordercolor=[("focus", c["gold"])])
        style.configure("TCombobox", fieldbackground=c["input"], background=c["input"],
                        foreground=c["bright"], arrowcolor=c["gold"], bordercolor=c["border"], padding=(6, 6))
        style.map("TCombobox", fieldbackground=[("readonly", c["input"])],
                  foreground=[("readonly", c["bright"])], selectbackground=[("readonly", c["input"])],
                  selectforeground=[("readonly", c["bright"])])
        self.root.option_add("*TCombobox*Listbox.background", c["panel_alt"])
        self.root.option_add("*TCombobox*Listbox.foreground", c["bright"])
        style.configure("Treeview", rowheight=27, background=c["panel_alt"],
                        fieldbackground=c["panel_alt"], foreground=c["bright"],
                        bordercolor=c["border"], font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10),
                        background=c["input"], foreground=c["gold"], relief="flat")
        style.map("Treeview", background=[("selected", c["teal"])],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", c["border"])])
        style.configure("Vertical.TScrollbar", background=c["panel_alt"],
                        troughcolor=c["base"], arrowcolor=c["gold"])

        heading = tk.Frame(self.root, bg=c["base"], highlightbackground=c["gold"], highlightthickness=1)
        heading.place(x=25, y=166, relwidth=1, width=-50, height=51)
        tk.Label(heading, text="CYBERLOG  /  ANALYZER", font=("Segoe UI", 19, "bold"),
                 fg=c["bright"], bg=c["base"]).pack(side="left", padx=17)
        tk.Label(heading, text="SECURITY EVENT ANALYSIS  •  FG", font=("Segoe UI", 10, "bold"),
                 fg=c["gold"], bg=c["base"]).pack(side="right", padx=18)

        shell = tk.Frame(self.root, bg=c["panel"], padx=17, pady=13,
                         highlightbackground=c["border"], highlightthickness=1)
        shell.place(x=25, y=230, relwidth=1, width=-50, relheight=1, height=-249)
        toolbar = tk.Frame(shell, bg=c["panel"])
        toolbar.pack(fill="x", pady=(0, 8))
        self._button(toolbar, "CSV megnyitása", self.choose_file).pack(side="left", padx=(0, 8))
        self._button(toolbar, "Mintanapló betöltése", lambda: self.load_file(BASE_DIR / "data" / "sample_log.csv")).pack(side="left", padx=(0, 8))
        self._button(toolbar, "CSV exportálása", self.export).pack(side="left")
        tk.Label(toolbar, text="●  OFFLINE ELEMZŐ", bg=c["panel"], fg=c["gold"],
                 font=("Segoe UI", 9, "bold")).pack(side="right")
        tk.Label(shell, textvariable=self.path_label, bg=c["panel"], fg=c["muted"],
                 anchor="w", font=("Segoe UI", 9)).pack(fill="x", pady=(0, 7))

        summary_box = tk.Frame(shell, bg=c["panel_alt"], padx=13, pady=10,
                               highlightbackground=c["border"], highlightthickness=1)
        summary_box.pack(fill="x", pady=(0, 10))
        tk.Label(summary_box, textvariable=self.summary, bg=c["panel_alt"], fg=c["mint"],
                 anchor="w", font=("Segoe UI Semibold", 10)).pack(fill="x")

        filters = tk.Frame(shell, bg=c["panel"])
        filters.pack(fill="x", pady=(0, 12))
        def field_title(text):
            return tk.Label(filters, text=text, bg=c["panel"], fg=c["muted"], font=("Segoe UI", 9))
        field_title("Forrás IP").pack(side="left", padx=(0, 5))
        ip_entry = ttk.Entry(filters, textvariable=self.ip_filter, width=18)
        ip_entry.pack(side="left", padx=(0, 14))
        ip_entry.bind("<KeyRelease>", lambda _: self.refresh_table())
        field_title("Státusz").pack(side="left", padx=(0, 5))
        select = ttk.Combobox(filters, textvariable=self.status_filter,
                              values=["Összes", "SUCCESS", "FAILED"], state="readonly", width=11)
        select.pack(side="left", padx=(0, 14))
        select.bind("<<ComboboxSelected>>", lambda _: self.refresh_table())
        field_title("Küszöb").pack(side="left", padx=(0, 5))
        ttk.Entry(filters, textvariable=self.threshold, width=5).pack(side="left", padx=(0, 14))
        field_title("Időablak (mp)").pack(side="left", padx=(0, 5))
        ttk.Entry(filters, textvariable=self.window_seconds, width=6).pack(side="left", padx=(0, 14))
        self._button(filters, "ELEMZÉS", self.analyze, accent=True).pack(side="left")

        panel = tk.Frame(shell, bg=c["panel"])
        panel.pack(fill="both", expand=True)
        left = tk.Frame(panel, bg=c["panel"])
        left.pack(side="left", fill="both", expand=True)
        self._section_title(left, "ESEMÉNYNAPLÓ")
        log_area = tk.Frame(left, bg=c["border"], padx=1, pady=1)
        log_area.pack(fill="both", expand=True, pady=(0, 10))
        self.tree = ttk.Treeview(log_area, columns=("time", "ip", "user", "status"), show="headings", height=12)
        for col, name, width in (("time", "Időpont", 170), ("ip", "Forrás IP", 120),
                                 ("user", "Felhasználó", 125), ("status", "Státusz", 95)):
            self.tree.heading(col, text=name)
            self.tree.column(col, width=width, minwidth=75)
        self.tree.tag_configure("failed", foreground=c["danger"])
        self.tree.tag_configure("success", foreground=c["mint"])
        scrollbar = ttk.Scrollbar(log_area, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self._section_title(left, "BRUTE-FORCE RIASZTÁSOK")
        self.alerts = tk.Text(left, height=6, bg=c["panel_alt"], fg=c["danger"],
                              insertbackground=c["bright"], font=("Consolas", 10),
                              relief="flat", wrap="word", padx=12, pady=10,
                              highlightbackground=c["border"], highlightthickness=1)
        self.alerts.pack(fill="x")
        self.alerts.configure(state="disabled")

        right = tk.Frame(panel, bg=c["panel"], width=350)
        right.pack(side="right", fill="y", padx=(16, 0))
        right.pack_propagate(False)
        self._section_title(right, "TOP 10 SIKERTELEN FORRÁS IP")
        self.chart = tk.Canvas(right, width=350, height=380, bg=c["panel_alt"],
                               highlightbackground=c["border"], highlightthickness=1)
        self.chart.pack(fill="x")
        tk.Label(right, text="Az észlelések szabályalapú figyelmeztetések,\nnem bizonyított támadások.",
                 justify="left", bg=c["panel"], fg=c["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(14, 0))
        self.root.after_idle(self._draw_background)

    def choose_file(self):
        path = filedialog.askopenfilename(title="Napló kiválasztása",
                                          filetypes=[("CSV fájl", "*.csv"), ("Minden fájl", "*.*")])
        if path:
            self.load_file(path)

    def load_file(self, path):
        try:
            count = self.analyzer.load_csv(path)
            self.path_label.set(f"BETÖLTVE: {path}    |    {count} esemény")
            self.refresh_table()
            self.analyze()
        except (OSError, ValueError, UnicodeError) as error:
            messagebox.showerror("Betöltési hiba", str(error))

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        frame = self.analyzer.filtered(self.ip_filter.get(), self.status_filter.get())
        for item in frame.head(1000).itertuples(index=False):
            tag = "failed" if item.status == "FAILED" else "success"
            self.tree.insert("", "end", values=(item.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                                                  item.source_ip, item.username, item.status), tags=(tag,))

    def analyze(self):
        try:
            threshold = int(self.threshold.get())
            seconds = int(self.window_seconds.get())
            detections = self.analyzer.fg_detect_bruteforce(threshold, seconds)
        except ValueError as error:
            messagebox.showerror("Érvénytelen beállítás", str(error))
            return
        stats = self.analyzer.statistics()
        self.summary.set(f"ÖSSZES: {stats['total']}     SIKERES: {stats['success']}     SIKERTELEN: {stats['failed']}     EGYEDI IP: {stats['unique_ips']}     RIASZTÁS: {len(detections)}")
        self.alerts.configure(state="normal")
        self.alerts.delete("1.0", "end")
        if detections:
            for alert in detections:
                self.alerts.insert("end", f"[GYANÚ] {alert.source_ip}  |  {alert.attempts} próbálkozás  |  {alert.window_start} – {alert.window_end}\n")
        else:
            self.alerts.insert("end", "Nem található a megadott szabálynak megfelelő esemény.")
        self.alerts.configure(state="disabled")
        self.draw_chart(stats["top_ips"])

    def draw_chart(self, entries):
        canvas = self.chart
        canvas.delete("all")
        if not entries:
            canvas.create_text(175, 150, text="Nincs sikertelen esemény", fill=COLORS["muted"], font=("Segoe UI", 12))
            return
        maximum = max(count for _, count in entries)
        for index, (ip, count) in enumerate(entries):
            y = 15 + index * 35
            bar_width = 175 * count / maximum
            canvas.create_text(12, y + 10, text=ip[:19], anchor="w", fill=COLORS["mint"], font=("Consolas", 9))
            canvas.create_rectangle(132, y + 3, 132 + bar_width, y + 19, fill=COLORS["teal"], outline="")
            canvas.create_line(132, y + 21, 132 + bar_width, y + 21, fill=COLORS["gold"])
            canvas.create_text(326, y + 10, text=str(count), anchor="e", fill=COLORS["gold"], font=("Segoe UI", 10, "bold"))

    def export(self):
        if self.analyzer.data.empty:
            messagebox.showinfo("Export", "Nincs exportálható adat.")
            return
        path = filedialog.asksaveasfilename(title="Szűrt adatok exportálása", defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            count = self.analyzer.export_csv(path, self.ip_filter.get(), self.status_filter.get())
            messagebox.showinfo("Export", f"{count} sor elmentve ide:\n{path}")
        except OSError as error:
            messagebox.showerror("Exportálási hiba", str(error))


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberLogApp(root)
    root.mainloop()
