# CyberLog Analyzer – Python projektfeladat

**Hallgató:** Furi Gábor  (BLAR9E)

## A program célja

Naplóelemző alkalmazás: CSV-ből beolvassa az autentikációs eseményeket, megjeleníti és szűri őket, összesítést és TOP 10 diagramot rajzol, valamint időablakos szabállyal brute-force gyanút jelez. A riasztás **heurisztika**, nem bizonyít tényleges támadást. A mintafájl mesterséges, a dokumentációs célokra fenntartott IP-tartományokat használja.

## Indítás PyCharmban (Windows)

1. `File > Open` alatt nyisd meg külön projektként a `CyberLog_Analyzer` mappát.
2. Állíts be Python 3.10+ interpretert a `Settings > Project > Python Interpreter` menüben. Használhatsz új virtuális környezetet (venv).
3. A PyCharm termináljában futtasd: `python -m pip install -r requirements.txt`.
4. Jobb klikk a `main.py` fájlon, majd `Run 'main'`.
5. Induláskor betöltődik a `data/sample_log.csv`, így az alkalmazás azonnal kipróbálható.

A grafikus felület a mellékelt `assets/cyber_background.png` hátteret használja, a harmonizáló gomb-, táblázat- és diagramstílusok a `main.py` fájlban találhatók. A képek megjelenítéséhez `Pillow` szükséges, ezt a `requirements.txt` automatikusan telepíti.

A `tkinter` a Python szabványos GUI modulja. Windows rendszeren a szokásos Python telepítővel elérhető. Ha nem települt, Python újratelepítése szükséges a Tcl/Tk komponenssel.

## Elvárt CSV-adatok

Az első sor fejléce pontosan tartalmazza a `timestamp,source_ip,username,status` oszlopokat. A timestamp ISO-formátumú időpont (például `2026-11-10 09:00:00`), a status `SUCCESS` vagy `FAILED`. Más oszlopok figyelmen kívül maradnak. 

## Használat

- **CSV megnyitása:** saját CSV kiválasztása.
- **Mintanapló:** ismét betölti a mellékelt példát.
- **IP-szűrő / Státusz:** a táblázat szűrése; a táblázat legfeljebb 1000 sort mutat, az elemzés minden sort feldolgoz.
- **Küszöb / Időablak:** például 5 sikertelen próbálkozás 60 másodpercen belül, forrás IP-címenként.
- **Elemzés:** újraszámolja a riasztásokat és összesítést.
- **CSV export:** a jelenlegi szűrésnek megfelelő összes sor mentése.

A szabály egy adott IP első küszöbátlépését jelzi; nem állít elő minden további, egymást átfedő ablakra külön riasztást.

## Modulok és függvények

| Modul | Típus | Felhasználás |
|---|---|---|
| `tkinter` / `tkinter.ttk` | grafikus, szabványkönyvtári | `Tk()`, `Treeview()`, `filedialog.askopenfilename()`, gombok és eseménykezelés |
| `Pillow` (`PIL`) | képfeldolgozó, külső | `Image.open()`, `ImageOps.fit()`, `ImageEnhance.Brightness()` és `ImageTk.PhotoImage()` |
| `pandas` | **bemutatandó**, külső | `read_csv()`, `to_datetime()`, `Series.value_counts()`, `DataFrame.groupby()`, `DataFrame.to_csv()` |
| `pathlib` | szabványkönyvtári | `Path()`, `is_file()` |
| `collections` | szabványkönyvtári | `deque()` |
| `fg_log_analyzer` | **saját modul** | `FGLogAnalyzer`, `FGDetection` |

**Saját osztály:** `FGLogAnalyzer`  
**Saját függvény/metódus:** `FGLogAnalyzer.fg_detect_bruteforce()`   
**További metódusok:** `load_csv()`, `statistics()`, `filtered()`, `export_csv()`  
**Eseménykezelés:** gombnyomás (`command`), szűrő gépelése (`<KeyRelease>`), legördülő változtatása (`<<ComboboxSelected>>`).


## Fájlszerkezet

- `main.py`: grafikus ablak (`root`) és alkalmazás (`app`), témaszínek és háttérkezelés
- `assets/cyber_background.png`: a felhasználó által mellékelt honvédelmi/kiberbiztonsági háttérkép
- `fg_log_analyzer.py`: a saját elemző modul
- `data/sample_log.csv`: szintetikus tesztadat
- `requirements.txt`: külső függőség
- `tests/test_analyzer.py`: automatizált ellenőrzések

## Tesztek

A projekt gyökerében: `python -m unittest discover -s tests -v`.

