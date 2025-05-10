import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import random
import time

class SnifferGUI:
    def __init__(self, master):
        self.master = master
        master.title("Sniffer 1.0")
        master.geometry("800x600")
        master.config(bg="#2C3E50")  # Dark Blue-Grey background

        # Main layout frame with a clean, centered design
        self.main_frame = tk.Frame(master, bg="#2C3E50")
        self.main_frame.pack(padx=20, pady=20, expand=True, fill=tk.BOTH)

        # Output text area with proper alignment and padding
        self.text_area = scrolledtext.ScrolledText(self.main_frame, height=15, width=100, bg="#34495E", fg="#ECF0F1", font=("Arial", 10), wrap=tk.WORD)
        self.text_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        # Filter checkboxes with clear labels and hover effect
        self.filters_frame = tk.Frame(self.main_frame, bg="#2C3E50")
        self.filters_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="w")

        self.tcp_var = tk.IntVar(value=1)
        self.udp_var = tk.IntVar(value=1)
        self.icmp_var = tk.IntVar(value=1)

        self.create_filter_checkbox(self.filters_frame, "TCP", self.tcp_var)
        self.create_filter_checkbox(self.filters_frame, "UDP", self.udp_var)
        self.create_filter_checkbox(self.filters_frame, "ICMP", self.icmp_var)

        # Active filter display with a more distinct style
        self.filter_display = tk.Label(self.main_frame, text="Active Filters: None", anchor="w", bg="#2C3E50", fg="#ECF0F1", font=("Arial", 12, "bold"))
        self.filter_display.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="w")

        # Control buttons
        self.controls_frame = tk.Frame(self.main_frame, bg="#2C3E50")
        self.controls_frame.grid(row=3, column=0, columnspan=3, pady=20)

        self.start_button = self.create_button(self.controls_frame, "Start Sniffing", self.start_sniffing)
        self.stop_button = self.create_button(self.controls_frame, "Stop Sniffing", self.stop_sniffing, state=tk.DISABLED)
        self.clear_button = self.create_button(self.controls_frame, "Clear Output", self.clear_output)
        self.save_button = self.create_button(self.controls_frame, "Save Output", self.save_output)

        # Status bar with better dynamic updates and interaction
        self.status_bar = tk.Label(self.main_frame, text="Status: Idle", anchor="w", relief=tk.SUNKEN, bg="#34495E", fg="#ECF0F1", font=("Arial", 12, "bold"))
        self.status_bar.grid(row=4, column=0, columnspan=3, sticky="w", padx=10, pady=5)

        self.sniff_thread = None

        # Update start button state based on filters
        self.tcp_var.trace_add("write", self.update_start_button_state)
        self.udp_var.trace_add("write", self.update_start_button_state)
        self.icmp_var.trace_add("write", self.update_start_button_state)

        # Configure grid columns to expand proportionally
        self.main_frame.grid_rowconfigure(0, weight=1)  # Text area takes up most space
        self.main_frame.grid_columnconfigure(0, weight=1)  # Allow columns to expand

    def create_filter_checkbox(self, frame, text, variable):
        check_button = tk.Checkbutton(frame, text=text, variable=variable, bg="#2C3E50", fg="#ECF0F1", font=("Arial", 12), selectcolor="#34495E", activebackground="#2C3E50")
        check_button.pack(side=tk.LEFT, padx=10)

    def create_button(self, frame, text, command, state=tk.NORMAL):
        button = tk.Button(frame, text=text, command=command, state=state, bg="#2980B9", fg="white", font=("Arial", 12), relief=tk.RAISED, bd=2, height=2, width=15, activebackground="#3498DB", activeforeground="white", highlightbackground="#2C3E50")
        button.pack(side=tk.LEFT, padx=10, pady=5)

        # Add hover effect
        button.bind("<Enter>", lambda e: button.config(bg="#3498DB"))
        button.bind("<Leave>", lambda e: button.config(bg="#2980B9"))

        return button

    def get_filters(self):
        filters = []
        if self.tcp_var.get(): filters.append('TCP')
        if self.udp_var.get(): filters.append('UDP')
        if self.icmp_var.get(): filters.append('ICMP')
        return filters

    def update_output(self, packet_details):
        # Safely update the output area
        self.master.after(0, self._insert_text, packet_details)

    def _insert_text(self, packet_details):
        self.text_area.insert(tk.END, packet_details + "\n")
        self.text_area.yview(tk.END)

    def update_filter_display(self):
        filters = self.get_filters()
        if filters:
            self.filter_display.config(text=f"Active Filters: {', '.join(filters)}")
        else:
            self.filter_display.config(text="Active Filters: None")

    def update_status(self, status, color="#ECF0F1"):
        self.status_bar.config(text=f"Status: {status}", fg=color)

    def update_start_button_state(self, *args):
        filters = self.get_filters()
        if filters:
            self.start_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.DISABLED)

    def start_sniffing(self):
        filters = self.get_filters()
        if not filters:
            messagebox.showwarning("No Filters", "Please select at least one filter!")
            return

        # Update status dynamically
        self.update_status("Sniffing in progress...", color="#4CAF50")
        self.update_filter_display()

        # Start sniffing in a separate thread
        self.sniff_thread = threading.Thread(target=start_sniff, args=(self.update_output, filters))  # Use start_sniff directly
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_sniffing(self):
        stop_sniff()  # Calling stop_sniff function
        self.update_status("Sniffer Stopped", color="#E74C3C")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def clear_output(self):
        if messagebox.askokcancel("Clear Output", "Are you sure you want to clear the output?"):
            self.text_area.delete(1.0, tk.END)

    def save_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.text_area.get(1.0, tk.END))
            messagebox.showinfo("Saved", "Output has been saved successfully!")

# Sniffer Code (example)
def start_sniff(update_output, filters):
    protocols = ['TCP', 'UDP', 'ICMP']
    packet_counter = 0
    
    while packet_counter < 20:  # Limit to 20 packets for simulation
        time.sleep(1)
        protocol = random.choice(protocols)
        packet_details = f"Packet {packet_counter + 1}: Src IP: 192.168.1.{packet_counter + 1}, Dst IP: 192.168.1.{packet_counter + 2}, Protocol: {protocol}, Size: 1500 bytes"
        update_output(packet_details)
        packet_counter += 1

def stop_sniff():
    # If you need to implement actual stop logic, you can add it here
    pass

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()
