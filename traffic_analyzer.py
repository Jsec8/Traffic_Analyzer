import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, Toplevel
import threading
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
from rich.console import Console
from datetime import datetime
import re

console = Console()

# Mapeo de puertos a protocolos comunes
port_protocols = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    179: "BGP",
    194: "IRC",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Authenticated)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1812: "RADIUS",
    1813: "RADIUS Accounting",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5500: "VNC",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    10000: "Webmin",
}

# Funciones para validaciones
def is_valid_ip(ip):
    """Valida si una IP es válida (IPv4)."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False

def is_valid_port(port):
    """Valida si un puerto está en el rango de puertos válidos (1-65535)."""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

# Configurar la ventana principal con Tkinter
class TrafficAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Traffic Analyzer")
        self.root.geometry("800x600")

        self.interface = tk.StringVar()
        self.filter_ip_src = tk.StringVar()
        self.filter_ip_dst = tk.StringVar()
        self.filter_port = tk.StringVar()
        
        self.file_name = None
        self.capturing = False
        self.sniffer_thread = None
        self.filter_protocol = None

        # Etiquetas e inputs
        tk.Label(root, text="Network Interface:").grid(row=0, column=0, padx=10, pady=10)
        self.interface_entry = tk.Entry(root, textvariable=self.interface)
        self.interface_entry.grid(row=0, column=1, padx=10, pady=10)
        
        tk.Label(root, text="Source IP Filter:").grid(row=1, column=0, padx=10, pady=10)
        self.src_ip_entry = tk.Entry(root, textvariable=self.filter_ip_src)
        self.src_ip_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(root, text="Destination IP Filter:").grid(row=2, column=0, padx=10, pady=10)
        self.dst_ip_entry = tk.Entry(root, textvariable=self.filter_ip_dst)
        self.dst_ip_entry.grid(row=2, column=1, padx=10, pady=10)

        tk.Label(root, text="Port Filter:").grid(row=3, column=0, padx=10, pady=10)
        self.port_entry = tk.Entry(root, textvariable=self.filter_port)
        self.port_entry.grid(row=3, column=1, padx=10, pady=10)

        # Botones
        button_style = {'padx': 10, 'pady': 10, 'bg': 'lightblue', 'fg': 'black'}
        tk.Button(root, text="Start Capture", command=self.start_capture_thread, **button_style).grid(row=5, column=0, padx=10, pady=10)
        tk.Button(root, text="Stop Capture", command=self.stop_capture, **button_style).grid(row=5, column=1, padx=10, pady=10)

        # Etiqueta para mostrar el estado
        self.status_label = tk.Label(root, text="Status: Waiting...", fg="green")
        self.status_label.grid(row=6, column=0, columnspan=4, padx=10, pady=10)

        # Tabla para mostrar los resultados
        self.tree = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Protocol", "Details"), show="headings", height=20)
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source (IP:Port)")
        self.tree.heading("Destination", text="Destination (IP:Port)")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Details", text="Details")
        self.tree.grid(row=7, column=0, columnspan=4, padx=10, pady=10, sticky='nsew')

        # Barra de desplazamiento para la tabla
        scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=7, column=4, sticky="ns")

        # Expandir tabla al cambiar tamaño ventana
        self.root.grid_rowconfigure(7, weight=1)
        self.root.grid_columnconfigure(3, weight=1)

        # Evento para abrir detalles del paquete al hacer clic en una fila
        self.tree.bind("<Double-1>", self.show_packet_details)

        # Almacenar paquetes capturados
        self.captured_packets = []

    # Función para analizar y mostrar el paquete capturado
    def analyze_packet(self, packet):
        capture_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_src, ip_dst, protocol, src_port, dst_port, details = None, None, None, None, None, ""

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = self.get_protocol(packet)
            if TCP in packet or UDP in packet:
                src_port = packet.sport
                dst_port = packet.dport
            details = f"TTL: {packet[IP].ttl}, ID: {packet[IP].id}, Len: {packet[IP].len}"
        elif IPv6 in packet:
            ip_src = packet[IPv6].src
            ip_dst = packet[IPv6].dst
            protocol = self.get_protocol(packet)
            if TCP in packet or UDP in packet:
                src_port = packet.sport
                dst_port = packet.dport
            details = f"Hop Limit: {packet[IPv6].hlim}, Flow Label: {packet[IPv6].fl}"

        if ip_src and ip_dst:
            source = f"{ip_src}:{src_port}" if src_port else ip_src
            destination = f"{ip_dst}:{dst_port}" if dst_port else ip_dst

            # Añadir el paquete a la tabla
            self.tree.insert("", "end", values=(capture_time, source, destination, protocol, details))

            # Guardar el paquete para detalles
            self.captured_packets.append((capture_time, packet))

            # Si estamos guardando, almacenar el paquete
            if self.file_name:
                self.save_packet(packet)

    # Función actualizada para obtener protocolo con más detalles
    def get_protocol(self, packet):
        if TCP in packet:
            port = packet.sport if packet.sport in port_protocols else packet.dport
            protocol_name = port_protocols.get(port, "TCP")
            return protocol_name
        elif UDP in packet:
            port = packet.sport if packet.sport in port_protocols else packet.dport
            protocol_name = port_protocols.get(port, "UDP")
            return protocol_name
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        else:
            return "Other"

    # Función para mostrar detalles del paquete
    def show_packet_details(self, event):
        selected_item = self.tree.selection()[0]
        packet_info = self.captured_packets[self.tree.index(selected_item)]
        capture_time, packet = packet_info

        # Crear una nueva ventana para mostrar los detalles
        detail_window = Toplevel(self.root)
        detail_window.title(f"Packet Details - {capture_time}")
        detail_window.geometry("600x400")

        packet_summary = packet.show(dump=True)

        # Mostrar el resumen del paquete en un cuadro de texto
        text_widget = tk.Text(detail_window, wrap="word")
        text_widget.insert("1.0", packet_summary)
        text_widget.config(state="disabled")
        text_widget.pack(expand=True, fill="both")

    # Función para capturar paquetes
    def start_capture(self):
        interface = self.interface.get()
        if not interface:
            messagebox.showerror("Error", "Please enter a network interface.")
            return

        # Validar IPs y puertos antes de comenzar
        if self.filter_ip_src.get() and not is_valid_ip(self.filter_ip_src.get()):
            messagebox.showerror("Error", "Invalid source IP address.")
            return
        if self.filter_ip_dst.get() and not is_valid_ip(self.filter_ip_dst.get()):
            messagebox.showerror("Error", "Invalid destination IP address.")
            return
        if self.filter_port.get() and not is_valid_port(self.filter_port.get()):
            messagebox.showerror("Error", "Invalid port number.")
            return

        filter_str = self.build_filter()

        try:
            self.status_label.config(text="Status: Capturing packets...", fg="blue")
            self.capturing = True
            sniff(iface=interface, prn=self.analyze_packet, filter=filter_str, store=0, stop_filter=self.should_stop)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {e}")
            self.status_label.config(text="Status: Waiting...", fg="red")

    # Función para construir el filtro basado en los campos del usuario
    def build_filter(self):
        filter_parts = []

        if self.filter_ip_src.get():
            filter_parts.append(f"src host {self.filter_ip_src.get()}")
        if self.filter_ip_dst.get():
            filter_parts.append(f"dst host {self.filter_ip_dst.get()}")
        if self.filter_port.get():
            port = self.filter_port.get()
        # Se captura solo el puerto específico para TCP o UDP
        filter_parts.append(f"(tcp port {port} or udp port {port})")

        return " and ".join(filter_parts)

    # Función para verificar si debemos detener la captura
    def should_stop(self, packet):
        return not self.capturing

    # Función para detener la captura
    def stop_capture(self):
        self.capturing = False
        self.status_label.config(text="Status: Stopped.", fg="red")
        self.ask_save_capture()

    # Función para capturar en hilo separado
    def start_capture_thread(self):
        self.sniffer_thread = threading.Thread(target=self.start_capture)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    # Ventana para preguntar si se desea guardar el archivo
    def ask_save_capture(self):
        if messagebox.askyesno("Save Capture", "Do you want to save the capture to a file?"):
            self.file_name = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if self.file_name:
                messagebox.showinfo("File Saved", f"Capture saved to {self.file_name}")
            else:
                messagebox.showwarning("No File", "No file was selected. Capture not saved.")

    # Función para guardar el tráfico capturado
    def save_packet(self, packet):
        with open(self.file_name, 'ab') as f:
            f.write(bytes(packet))

# Crear la ventana y ejecutar la aplicación
root = tk.Tk()
app = TrafficAnalyzerApp(root)
root.mainloop()


















