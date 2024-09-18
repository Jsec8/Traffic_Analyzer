# Traffic Analyzer

## Overview

The Traffic Analyzer is a network packet capture and analysis tool built with Python using the Tkinter library for the GUI and Scapy for packet analysis. This tool allows you to capture network traffic, filter it by IP addresses and ports, and view detailed information about each packet.

## Features

- Capture network traffic from a specified network interface.
- Filter packets by source IP, destination IP, or port.
- Display captured packets in a user-friendly table.
- View detailed packet information in a separate window.
- Save captured packets to a PCAP file.

## Requirements

- Python 3.x
- Tkinter
- Scapy
- Rich (for enhanced console output)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Jsec8/Traffic_Analyzer.git
    ```

2. Navigate to the project directory:

    ```bash
    cd traffic-analyzer
    ```

3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Open the application:

    ```bash
    python traffic_analyzer.py
    ```

2. Enter the network interface you want to capture traffic from.
3. Optionally, set filters for source IP, destination IP, or port.
4. Click "Start Capture" to begin capturing packets.
5. View the captured packets in the table and double-click to see detailed information.
6. Click "Stop Capture" when you are finished, and choose to save the capture to a file if desired.

## License

This project is licensed under the MIT License. See the [LICENSE.txt] file for details.

## Contact

For any questions or issues, please contact [juanisaac9307@gmail.com].
