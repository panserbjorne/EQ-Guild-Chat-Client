"""
main.py — Entry point for EQ Guild Chat Client.
"""

import tkinter as tk

from config import APP_NAME, Config
from gui import App
import updater


def main():
    updater.cleanup_old()   # the exe a previous update replaced
    config = Config()
    root   = tk.Tk()
    root.iconname(APP_NAME)

    app = App(root, config)
    root.mainloop()


if __name__ == "__main__":
    main()