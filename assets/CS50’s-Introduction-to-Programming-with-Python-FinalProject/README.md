# Network Traffic Analysis for DDoS Detection with Python

#### Description:
This project is aimed at analyzing network traffic to detect potential Distributed Denial of Service (DDoS) attacks. The focus of the project is to utilize Python's capabilities in processing and analyzing packet data captured from a network, identifying anomalous behaviors that could indicate a DDoS attack.

### Project Overview:

This project is built upon Python, leveraging its libraries and frameworks to analyze network traffic data. It is encapsulated within a `project.py` script, comprising several functions critical for parsing network data, identifying potential security threats, and providing statistical insights into network traffic patterns. To ensure the reliability and functionality of the code, I have also included a testing script, `test_project.py`, which performs unit tests on the custom functions defined in `project.py`.

### Project Files and Their Functions:

- **`project.py`**: This is the core script of the project. It contains four primary functions:
    1. `convert_to_csv(pcapng_path, csv_path)`: Converts packet data from `.pcapng` files to `.csv` for easier analysis.
    2. `parse_data(file_path)`: Reads the converted `.csv` file and organizes the data into a structured format for further analysis.
    3. `detect_ddos(packets, threshold)`: Analyzes the structured packet data to identify IPs with suspiciously high traffic volumes, potentially indicating a DDoS attack.
    4. `average_size(packets)`: Calculates the average size of the packets in the dataset, aiding in the identification of anomalous packet sizes that may signify an attack.

- **`test_project.py`**: Contains unit tests for the functions in `project.py`, ensuring each function's accuracy and reliability. The tests include:
    - `test_convert_to_csv()`: Tests the packet data conversion functionality.
    - `test_parse_data()`: Verifies the CSV data parsing capability.
    - `test_detect_ddos()`: Checks the DDoS detection logic against simulated packet data.
    - `test_average_size()`: Ensures accurate calculation of average packet size.

- **`traffic.pcapng` and `traffic.csv`**: Sample data files used for testing and demonstration purposes. `traffic.pcapng` is the original packet capture file, while `traffic.csv` is the result of converting `traffic.pcapng` using `convert_to_csv`.

### Theoretical and Practical Implications:

The project is built on the idea of network security and analyzing traffic patterns to detect anomalies. DDoS attacks are difficult to identify because of the overwhelming amount of traffic.

### Installation and Dependencies

To run this project, you must have Python installed on your machine along with several pip installable libraries. Below are the installation commands for the required libraries:

```bash
pip install pyshark
pip install pytest
