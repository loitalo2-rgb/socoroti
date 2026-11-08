"""Ponto de entrada para PyInstaller e execucao direta.

Uso:
    python socorro.py rede diagnostico
    pyinstaller --onefile --name socorro socorro.py
"""

from socoroti.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
