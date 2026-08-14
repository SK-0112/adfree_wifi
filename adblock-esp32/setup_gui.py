#!/usr/bin/env python3
"""
AdFree Flasher — desktop installer for the ESP32-S3 ad blocker.

Most people should use the web installer instead; it needs nothing installed:
    https://SK-0112.github.io/adfree_wifi/

This tool exists for the cases the browser can't cover:
  * flashing without an internet connection
  * baking Wi-Fi credentials into the image, so a board you post to a relative
    joins their network the moment they plug it in

Runs on Windows, Linux and macOS.

Run it with:      python setup_gui.py
"""

import os
import platform
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(PROJECT_DIR)
SEED_HEADER = os.path.join(PROJECT_DIR, "src", "seed_credentials.h")
PREBUILT_DIR = os.path.join(REPO_DIR, "docs", "firmware")
ESPRESSIF_VID = 0x303A

# ---- palette -----------------------------------------------------------------
BG = "#0b0d12"
CARD = "#151922"
LINE = "#232838"
FG = "#e9ecf3"
MUTED = "#98a1b3"
FIELD = "#0a0c11"
ACCENT = "#4f8cff"
ACCENT_HOVER = "#3d7bf0"
OK = "#37d39b"
WARN = "#f0c48a"
ERR = "#ff6b6b"

# Resolved against the fonts actually installed, once Tk is up. Segoe UI only
# exists on Windows and Consolas usually doesn't exist on Linux, so asking for
# them by name elsewhere silently falls back to Tk's ugly default.
UI = "TkDefaultFont"
MONO = "TkFixedFont"
BULLET = "*"


def pick_fonts():
    """Choose the best available UI and monospace family for this OS."""
    global UI, MONO, BULLET
    have = {f.lower(): f for f in tkfont.families()}

    def first(*names):
        for n in names:
            if n.lower() in have:
                return have[n.lower()]
        return None

    UI = first("Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Cantarell",
               "Ubuntu", "Noto Sans", "DejaVu Sans", "Liberation Sans") or UI
    MONO = first("Consolas", "SF Mono", "Menlo", "JetBrains Mono", "DejaVu Sans Mono",
                 "Liberation Mono", "Ubuntu Mono", "Noto Sans Mono") or MONO

    # Tk on some X11 setups renders U+2022 as a missing-glyph box in Entry widgets.
    try:
        BULLET = "•" if tkfont.Font(family=UI).measure("•") > 0 else "*"
    except tk.TclError:
        BULLET = "*"


def serial_permission_hint():
    """On Linux the port exists but is root-only until the user is in dialout."""
    if platform.system() != "Linux":
        return ""
    return ("\n\nOn Linux the serial port is owned by the 'dialout' group. If the board "
            "is plugged in but doesn't appear, or writing fails with a permission "
            "error, run:\n\n    sudo usermod -aG dialout $USER\n\n"
            "then log out and back in.")


def find_boards():
    """Return [(label, device, is_esp)] for attached serial ports, Espressif first."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    found = []
    for p in list_ports.comports():
        is_esp = (p.vid == ESPRESSIF_VID)
        desc = "ESP32-S3 board" if is_esp else (p.description or "serial port")
        found.append((0 if is_esp else 1, f"{p.device}  ·  {desc}", p.device, is_esp))
    found.sort()
    return [(lbl, dev, esp) for _, lbl, dev, esp in found]


def find_prebuilt():
    """Newest merged release image shipped in docs/firmware/, if there is one."""
    if not os.path.isdir(PREBUILT_DIR):
        return None
    imgs = [os.path.join(PREBUILT_DIR, f) for f in os.listdir(PREBUILT_DIR)
            if f.startswith("adfree-esp32s3-") and f.endswith(".bin")]
    return max(imgs, key=os.path.getmtime) if imgs else None


def esptool_write_cmd():
    """esptool 5 renamed the subcommands; 4.x only knows the underscore forms."""
    try:
        out = subprocess.run([sys.executable, "-m", "esptool", "version"],
                             capture_output=True, text=True, timeout=30).stdout
        major = int(re.search(r"(\d+)\.", out.strip().splitlines()[-1]).group(1))
    except Exception:
        major = 4
    return ("write-flash", "erase-flash") if major >= 5 else ("write_flash", "erase_flash")


def c_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


class Card(tk.Frame):
    """A titled panel. Everything on the form lives in one of these."""

    def __init__(self, parent, title, subtitle=None):
        super().__init__(parent, bg=CARD, highlightbackground=LINE,
                         highlightcolor=LINE, highlightthickness=1)
        pad = tk.Frame(self, bg=CARD, padx=18, pady=15)
        pad.pack(fill="both", expand=True)
        tk.Label(pad, text=title, bg=CARD, fg=FG,
                 font=(UI, 10, "bold")).pack(anchor="w")
        if subtitle:
            tk.Label(pad, text=subtitle, bg=CARD, fg=MUTED, font=(UI, 9),
                     justify="left").pack(anchor="w", pady=(1, 0))
        self.body = tk.Frame(pad, bg=CARD)
        self.body.pack(fill="both", expand=True, pady=(11, 0))


class App:
    def __init__(self, root):
        self.root = root
        self.proc = None
        self.q = queue.Queue()
        self.ports = []
        self.log_shown = False

        root.title("AdFree Flasher")
        root.configure(bg=BG)
        root.geometry("640x760")
        root.minsize(600, 640)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TCombobox", fieldbackground=FIELD, background=CARD,
                        foreground=FG, arrowcolor=MUTED, bordercolor=LINE,
                        lightcolor=LINE, darkcolor=LINE, selectbackground=FIELD,
                        selectforeground=FG, padding=6)
        root.option_add("*TCombobox*Listbox.background", CARD)
        root.option_add("*TCombobox*Listbox.foreground", FG)
        root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        style.configure("Bar.Horizontal.TProgressbar", troughcolor=FIELD, bordercolor=LINE,
                        background=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT, thickness=5)

        outer = tk.Frame(root, bg=BG, padx=22, pady=20)
        outer.pack(fill="both", expand=True)

        # ---------------- header ----------------
        tk.Label(outer, text="AdFree Flasher", bg=BG, fg=FG,
                 font=(UI, 18, "bold")).pack(anchor="w")
        tk.Label(outer, text="Write the ad-blocker firmware to an ESP32-S3 board.",
                 bg=BG, fg=MUTED, font=(UI, 9)).pack(anchor="w", pady=(2, 18))

        # ---------------- board ----------------
        c1 = Card(outer, "1 · Board",
                  "Connect it with a USB cable that carries data, not a charge-only one.")
        c1.pack(fill="x")
        c1.body.columnconfigure(0, weight=1)
        self.port_cb = ttk.Combobox(c1.body, state="readonly", font=(UI, 10))
        self.port_cb.grid(row=0, column=0, sticky="ew")
        self._ghost(c1.body, "Refresh", self.refresh_ports).grid(row=0, column=1, padx=(8, 0))

        # ---------------- mode ----------------
        c2 = Card(outer, "2 · Wi-Fi", "How the board learns which network to join.")
        c2.pack(fill="x", pady=(12, 0))
        self.mode = tk.StringVar(value="portal")
        self._radio(c2.body, "portal",
                    "Set it up from a phone afterwards",
                    "Recommended. Takes about 40 seconds and needs no build tools. "
                    "The board opens its own ADFREE-XXXX hotspot on first boot.").pack(anchor="w", fill="x")
        self._radio(c2.body, "seed",
                    "Bake the Wi-Fi in now",
                    "For a board you're giving to someone else. Compiles from source, "
                    "so it takes a few minutes and needs PlatformIO.").pack(anchor="w", fill="x", pady=(9, 0))

        self.fields = tk.Frame(c2.body, bg=CARD)
        self.fields.columnconfigure(1, weight=1)
        self.ssid = self._field(0, "Wi-Fi name (SSID)")
        self.wpass = self._field(1, "Wi-Fi password", show=BULLET)
        self.apass = self._field(2, "Dashboard password", show=BULLET)
        self.apass.insert(0, "adblock123")
        self.show_var = tk.IntVar()
        self._check(self.fields, "Show passwords", self.show_var,
                    command=self.toggle_show).grid(row=3, column=1, sticky="w", padx=(12, 0),
                                                   pady=(6, 0))

        # ---------------- options ----------------
        c3 = Card(outer, "3 · Options")
        c3.pack(fill="x", pady=(12, 0))
        self.erase_var = tk.IntVar(value=1)
        self._check(c3.body, "Erase the board completely first  (recommended for a new board)",
                    self.erase_var).pack(anchor="w")

        # ---------------- action ----------------
        self.btn = tk.Button(outer, text="Install AdFree", command=self.start,
                             bg=ACCENT, fg="white", relief="flat", bd=0,
                             font=(UI, 11, "bold"), pady=12, cursor="hand2",
                             activebackground=ACCENT_HOVER, activeforeground="white")
        self.btn.pack(fill="x", pady=(18, 0))
        self.btn.bind("<Enter>", lambda e: self.btn.config(bg=ACCENT_HOVER)
                      if str(self.btn["state"]) == "normal" else None)
        self.btn.bind("<Leave>", lambda e: self.btn.config(bg=ACCENT)
                      if str(self.btn["state"]) == "normal" else None)

        self.bar = ttk.Progressbar(outer, style="Bar.Horizontal.TProgressbar",
                                   mode="determinate", maximum=100)
        self.bar.pack(fill="x", pady=(12, 6))

        srow = tk.Frame(outer, bg=BG)
        srow.pack(fill="x")
        self.status = tk.Label(srow, text="Ready.", bg=BG, fg=MUTED,
                               font=(UI, 9), anchor="w")
        self.status.pack(side="left")
        self.details = tk.Label(srow, text="Show details", bg=BG, fg=MUTED,
                                font=(UI, 9, "underline"), cursor="hand2")
        self.details.pack(side="right")
        self.details.bind("<Button-1>", lambda e: self.toggle_log())

        self.logwrap = tk.Frame(outer, bg=BG)
        self.log = scrolledtext.ScrolledText(self.logwrap, bg=FIELD, fg=MUTED, relief="flat",
                                             font=(MONO, 8), height=12, wrap="word",
                                             insertbackground=FG, borderwidth=0)
        self.log.pack(fill="both", expand=True)

        self.toggle_mode()
        self.refresh_ports()
        self.root.after(100, self.drain)

    # ---------------- small widget builders ----------------
    def _ghost(self, parent, text, cmd):
        return tk.Button(parent, text=text, command=cmd, bg="#1e2430", fg=FG, relief="flat",
                         bd=0, font=(UI, 9), padx=14, pady=6, cursor="hand2",
                         activebackground="#28303f", activeforeground=FG)

    def _check(self, parent, text, var, command=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=command,
                              bg=CARD, fg=MUTED, selectcolor=FIELD, activebackground=CARD,
                              activeforeground=FG, font=(UI, 9), bd=0,
                              highlightthickness=0, anchor="w", cursor="hand2")

    def _radio(self, parent, value, title, blurb):
        f = tk.Frame(parent, bg=CARD)
        tk.Radiobutton(f, text=title, variable=self.mode, value=value, command=self.toggle_mode,
                       bg=CARD, fg=FG, selectcolor=FIELD, activebackground=CARD,
                       activeforeground=FG, font=(UI, 9, "bold"), bd=0,
                       highlightthickness=0, cursor="hand2").pack(anchor="w")
        tk.Label(f, text=blurb, bg=CARD, fg=MUTED, font=(UI, 8), justify="left",
                 wraplength=520).pack(anchor="w", padx=(23, 0))
        return f

    def _field(self, row, label, show=None):
        tk.Label(self.fields, text=label, bg=CARD, fg=MUTED,
                 font=(UI, 9)).grid(row=row, column=0, sticky="w", pady=(7, 0))
        e = tk.Entry(self.fields, bg=FIELD, fg=FG, insertbackground=FG, relief="flat",
                     font=(UI, 10), show=show, highlightthickness=1,
                     highlightbackground=LINE, highlightcolor=ACCENT)
        e.grid(row=row, column=1, sticky="ew", padx=(12, 0), ipady=5, pady=(7, 0))
        return e

    # ---------------- ui state ----------------
    def toggle_show(self):
        ch = "" if self.show_var.get() else BULLET
        self.wpass.config(show=ch)
        self.apass.config(show=ch)

    def toggle_mode(self):
        if self.mode.get() == "seed":
            self.fields.pack(fill="x", pady=(12, 0))
        else:
            self.fields.pack_forget()

    def toggle_log(self):
        self.log_shown = not self.log_shown
        if self.log_shown:
            self.logwrap.pack(fill="both", expand=True, pady=(10, 0))
            self.details.config(text="Hide details")
        else:
            self.logwrap.pack_forget()
            self.details.config(text="Show details")

    def refresh_ports(self):
        self.ports = find_boards()
        self.port_cb["values"] = [b[0] for b in self.ports] or ["No board detected"]
        self.port_cb.current(0)
        if self.ports and self.ports[0][2]:
            self.set_status(f"Found {self.ports[0][1]}.", OK)
        elif self.ports:
            self.set_status("No ESP32 recognised — pick the right port yourself.", WARN)
        else:
            self.set_status("No board found. Plug it in, then press Refresh.", WARN)

    def set_status(self, text, color=MUTED):
        self.status.config(text=text, fg=color)

    def write(self, t):
        self.log.insert("end", t)
        self.log.see("end")

    def drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.write(payload)
                elif kind == "status":
                    self.set_status(payload)
                elif kind == "progress":
                    self.bar.config(mode="determinate")
                    self.bar["value"] = payload
                elif kind == "busy":
                    self.bar.config(mode="indeterminate")
                    self.bar.start(14)
                elif kind == "done":
                    self.finish(payload)
        except queue.Empty:
            pass
        self.root.after(100, self.drain)

    # ---------------- flashing ----------------
    def start(self):
        if not self.ports:
            messagebox.showerror("No board",
                                 "No serial port found.\n\nPlug the board in with a data "
                                 "cable, then press Refresh." + serial_permission_hint())
            return
        port = self.ports[self.port_cb.current()][1]
        seed = self.mode.get() == "seed"

        if seed:
            ssid = self.ssid.get().strip()
            if not ssid:
                messagebox.showerror("Missing Wi-Fi", "Enter the Wi-Fi network name.")
                return
            if len(self.apass.get()) < 8:
                messagebox.showerror("Password too short",
                                     "The dashboard password must be at least 8 characters.")
                return
            try:
                with open(SEED_HEADER, "w", encoding="utf-8") as f:
                    f.write("// generated by setup_gui.py - never commit this file\n#pragma once\n")
                    f.write(f'#define SEED_WIFI_SSID "{c_escape(ssid)}"\n')
                    f.write(f'#define SEED_WIFI_PASS "{c_escape(self.wpass.get())}"\n')
                    f.write(f'#define SEED_ADMIN_PASS "{c_escape(self.apass.get())}"\n')
            except OSError as e:
                messagebox.showerror("Error", f"Could not write the settings file:\n{e}")
                return
        elif find_prebuilt() is None:
            messagebox.showerror(
                "No firmware image",
                "No prebuilt image found in docs/firmware/.\n\n"
                "Build one with:\n    python tools/build_release.py\n\n"
                "…or choose \"Bake the Wi-Fi in now\", which compiles from source.")
            return

        self.btn.config(state="disabled", text="Installing…", bg="#2a3040", cursor="")
        self.bar["value"] = 0
        self.log.delete("1.0", "end")
        self.write(f"Board  {port}\n")
        self.write(f"Wi-Fi  {'baked in' if seed else 'set up from a phone afterwards'}\n")
        self.write(f"Erase  {'yes' if self.erase_var.get() else 'no'}\n\n")
        threading.Thread(target=self.run, args=(port, seed), daemon=True).start()

    def build_commands(self, port, seed):
        write_flash, erase_flash = esptool_write_cmd()
        esp = ["-m", "esptool", "--chip", "esp32s3", "--port", port]
        cmds = []
        if self.erase_var.get():
            cmds.append((esp + [erase_flash], "Erasing the board…"))
        if seed:
            # Credentials are compile-time, so this path has to go through a build.
            cmds.append((["-m", "platformio", "run", "-e", "seeded", "-t", "upload",
                          "--upload-port", port], "Building and uploading…"))
        else:
            # The merged image starts at offset 0 and carries its own boot selector,
            # so it also fixes a board that last booted from the OTA slot.
            cmds.append((esp + ["--baud", "921600", write_flash, "0x0", find_prebuilt()],
                         "Writing firmware…"))
        return cmds

    def run(self, port, seed):
        env = dict(os.environ)
        env["PLATFORMIO_DISABLE_PROGRESSBAR"] = "true"
        # CREATE_NO_WINDOW is Windows-only; the ternary keeps it unevaluated elsewhere.
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        denied = False

        for args, status in self.build_commands(port, seed):
            cmd = [sys.executable] + args
            self.q.put(("status", status))
            self.q.put(("busy", None))
            self.q.put(("log", "$ " + " ".join(cmd[1:]) + "\n"))
            try:
                self.proc = subprocess.Popen(cmd, cwd=PROJECT_DIR, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, bufsize=1,
                                             env=env, creationflags=flags)
            except FileNotFoundError:
                tool = "PlatformIO" if "platformio" in args else "esptool"
                self.q.put(("done", f"{tool} is not installed for this Python.\n\n"
                                    f"Install it with:\n    "
                                    f"{os.path.basename(sys.executable)} -m pip install "
                                    f"{'platformio' if tool == 'PlatformIO' else 'esptool'}"))
                return
            except Exception as e:
                self.q.put(("done", f"Could not start the flashing tool:\n{e}"))
                return
            for line in self.proc.stdout:
                self.q.put(("log", line))
                low = line.lower()
                if "permission denied" in low or "could not open port" in low:
                    denied = True
                if "compiling" in low:
                    self.q.put(("status", "Compiling firmware…"))
                elif "linking" in low:
                    self.q.put(("status", "Linking…"))
                elif "writing at" in low:
                    m = re.search(r"\((\d+)\s*%\)", line)
                    if m:
                        self.q.put(("status", f"Writing firmware… {m.group(1)}%"))
                        self.q.put(("progress", int(m.group(1))))
            self.proc.wait()
            if self.proc.returncode != 0:
                msg = (f"Failed while: {status}\n"
                       f"Exit code {self.proc.returncode}.\n\n"
                       f"Open \"Show details\" for the full output.")
                if denied:
                    msg += ("\n\nThe serial port could not be opened — something else may "
                           "be holding it (a serial monitor, the Arduino IDE)."
                           + serial_permission_hint())
                self.q.put(("done", msg))
                return
            self.q.put(("log", "\n"))
        self.q.put(("done", ""))

    def finish(self, err):
        self.bar.stop()
        self.bar.config(mode="determinate")
        self.btn.config(state="normal", text="Install AdFree", bg=ACCENT, cursor="hand2")
        self.proc = None
        if err:
            self.bar["value"] = 0
            self.set_status("Failed.", ERR)
            messagebox.showerror("Installation failed", err)
            return

        self.bar["value"] = 100
        self.set_status("Done — the board is ready.", OK)
        if self.mode.get() == "seed":
            messagebox.showinfo(
                "Done",
                "The board is set up for '%s'.\n\n"
                "1. Unplug it and power it from any USB charger.\n"
                "2. It joins the Wi-Fi on its own within a few seconds.\n"
                "3. Open  http://adblock.local  to see its IP address.\n"
                "4. In the router's settings, set the DNS server to that\n"
                "    address and reserve the IP for this board.\n\n"
                "If it can't join, it falls back to its own ADFREE-XXXX hotspot."
                % self.ssid.get().strip())
        else:
            messagebox.showinfo(
                "Done",
                "The board is flashed.\n\n"
                "1. Unplug it and power it from any USB charger.\n"
                "2. On your phone, join the Wi-Fi network  ADFREE-XXXX\n"
                "    Its password is unique to this board and is printed on\n"
                "    the serial console while the setup portal is running.\n"
                "3. A setup page opens — enter your home Wi-Fi and choose a\n"
                "    password for the dashboard.\n"
                "4. Open  http://adblock.local, then point the router's DNS\n"
                "    server at the IP address it shows.")


def main():
    missing = []
    for mod, pkg in (("serial", "pyserial"), ("esptool", "esptool")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("Missing dependencies. Run:\n\n"
              f"    {sys.executable} -m pip install {' '.join(missing)}\n\n"
              "Add 'platformio' too if you want to bake Wi-Fi credentials in.")
        return 1

    try:
        root = tk.Tk()
    except tk.TclError as e:
        # Headless Linux, or Tk not installed alongside Python.
        print(f"Could not open a window: {e}\n")
        if platform.system() == "Linux":
            print("On Debian/Ubuntu install Tk with:  sudo apt install python3-tk")
        print("\nYou can flash without a GUI instead:\n"
              "    python -m esptool --chip esp32s3 write-flash 0x0 "
              "docs/firmware/adfree-esp32s3-*.bin")
        return 1

    pick_fonts()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
