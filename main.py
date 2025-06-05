import tkinter as tk
from gui import SecureP2PGUI


def main():
    root = tk.Tk()
    app = SecureP2PGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
