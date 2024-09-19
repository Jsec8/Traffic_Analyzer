import tkinter as tk
from tkinter import ttk, messagebox, filedialog, Toplevel
import threading
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
from scapy.utils import wrpcap
from rich.console import Console
from datetime import datetime
import re

console = Console()

# Mapeo de puertos a protocolos comunes
port_protocols = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "Microsoft RPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    179: "BGP", 194: "IRC", 443: "HTTPS", 465: "SMTPS", 587: "SMTP (Authenticated)",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1434: "MSSQL Monitor", 
    1812: "RADIUS", 1813: "RADIUS Accounting", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5500: "VNC", 5900: "VNC", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 10000: "Webmin",
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
        self.filter_ip = tk.StringVar()
        self.filter_port = tk.StringVar()
        
        self.file_name = None
        self.capturing = False
        self.sniffer_thread = None

        # Etiquetas e inputs
        tk.Label(root, text="Network Interface:").grid(row=0, column=0, padx=10, pady=10)
        self.interface_entry = tk.Entry(root, textvariable=self.interface)
        self.interface_entry.grid(row=0, column=1, padx=10, pady=10)
        
        tk.Label(root, text="IP Filter:").grid(row=1, column=0, padx=10, pady=10)
        self.ip_entry = tk.Entry(root, textvariable=self.filter_ip)
        self.ip_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(root, text="Port Filter:").grid(row=2, column=0, padx=10, pady=10)
        self.port_entry = tk.Entry(root, textvariable=self.filter_port)
        self.port_entry.grid(row=2, column=1, padx=10, pady=10)

        # Botones
        button_style = {'padx': 10, 'pady': 10, 'bg': 'lightblue', 'fg': 'black'}
        tk.Button(root, text="Start Capture", command=self.start_capture_thread, **button_style).grid(row=4, column=0, padx=10, pady=10)
        tk.Button(root, text="Stop Capture", command=self.stop_capture, **button_style).grid(row=4, column=1, padx=10, pady=10)

        # Etiqueta para mostrar el estado
        self.status_label = tk.Label(root, text="Status: Waiting...", fg="green")
        self.status_label.grid(row=5, column=0, columnspan=4, padx=10, pady=10)

        # Tabla para mostrar los resultados
        self.tree = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Protocol", "Details"), show="headings", height=20)
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source (IP:Port)")
        self.tree.heading("Destination", text="Destination (IP:Port)")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Details", text="Details")
        self.tree.grid(row=6, column=0, columnspan=4, padx=10, pady=10, sticky='nsew')

        # Barra de desplazamiento para la tabla
        scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=6, column=4, sticky="ns")

        # Expandir tabla al cambiar tamaño ventana
        self.root.grid_rowconfigure(6, weight=1)
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

        # Aplicar un filtro adicional al nivel de la aplicación para asegurarnos de que el puerto es el correcto
        filter_port = self.filter_port.get().strip()
        if filter_port:
            if src_port and dst_port:
                if not (str(src_port) == filter_port or str(dst_port) == filter_port):
                    return  # Ignorar paquetes que no coinciden con el puerto filtrado

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
        elif ICMP in packet:
            return "ICMP"
        elif ARP in packet:
            return "ARP"
        else:
            return packet.summary()

    # Mostrar detalles de un paquete en una ventana emergente
    def show_packet_details(self, event):
        item = self.tree.selection()[0]
        packet_index = self.tree.index(item)
        packet = self.captured_packets[packet_index][1]

        details_window = Toplevel(self.root)
        details_window.title("Packet Details")
        details_window.geometry("500x400")

        packet_text = tk.Text(details_window)
        packet_text.pack(expand=True, fill=tk.BOTH)

        packet_text.insert(tk.END, packet.show(dump=True))

    # Iniciar captura en un hilo separado
    def start_capture_thread(self):
        if not self.capturing:
            self.capturing = True
            self.sniffer_thread = threading.Thread(target=self.start_capture)
            self.sniffer_thread.daemon = True  # Permite cerrar el hilo con la aplicación
            self.sniffer_thread.start()

    # Función para iniciar la captura
    def start_capture(self):
        try:
            interface = self.interface.get()
            if not interface:
                raise ValueError("Network interface is required.")

            # Construir filtro de captura basado en la entrada del usuario
            capture_filter = self.build_filter()

            self.update_status("Status: Capturing...", "red")

            sniff(iface=interface, filter=capture_filter, prn=self.analyze_packet, store=False, stop_filter=lambda _: not self.capturing)

        except Exception as e:
            self.show_error_message(str(e))

    # Detener la captura y guardar archivo
    def stop_capture(self):
        if self.capturing:
            self.capturing = False
            self.update_status("Status: Stopped.", "green")

            # Mostrar ventana para guardar archivo
            self.file_name = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if self.file_name:
                messagebox.showinfo("Save", f"Packets saved to {self.file_name}")

    # Función para construir filtro de captura basado en los filtros proporcionados
    def build_filter(self):
        filters = []

        ip_filter = self.filter_ip.get().strip()
        port = self.filter_port.get().strip()

        if ip_filter:
            if is_valid_ip(ip_filter):
                filters.append(f"host {ip_filter}")
            else:
                raise ValueError("Invalid IP address.")

        if port:
            if is_valid_port(port):
                # Filtrar tanto para TCP como UDP en el puerto dado (como origen o destino)
                filters.append(f"(tcp port {port} or udp port {port})")
            else:
                raise ValueError("Invalid port number.")

        return " and ".join(filters) if filters else None

    # Guardar paquete en archivo pcap
    def save_packet(self, packet):
        wrpcap(self.file_name, packet, append=True)

    # Actualizar el estado de la aplicación en la interfaz de usuario
    def update_status(self, message, color):
        self.root.after(0, lambda: self.status_label.config(text=message, fg=color))

    # Mostrar mensaje de error en la interfaz de usuario desde el hilo de la GUI
    def show_error_message(self, message):
        self.root.after(0, lambda: console.log(f"Error: {message}"))  # Cambiado para evitar pop-ups.

    # Cerrar ventana de manera segura
    def on_closing(self):
        if self.capturing:
            self.stop_capture()  # Asegurarse de que la captura se detiene
        self.root.quit()  # Cerrar la ventana de forma segura

# Crear la aplicación
root = tk.Tk()
app = TrafficAnalyzerApp(root)
root.protocol("WM_DELETE_WINDOW", app.on_closing)  # Llamar a on_closing al cerrar la ventana
root.mainloop()




























