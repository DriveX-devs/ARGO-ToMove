# ARGO (Ai-driven framewoRk for CountinG peOple) ToMove - Wireless People Counting Framework enhanced in the ToMove project

## Main reference paper for the original ARGO

We have a reference paper for the original work on ARGO:

> R. Rusca, D. Gasco, C. Casetti and P. Giaccone, "Privacy-preserving WiFi fingerprint-based people counting for crowd management" - Computer Communications, 2024 [URL](https://www.sciencedirect.com/science/article/pii/S0140366424002482) [BibTeX](/cite.bib)

The ARGO-ToMove framework, developed in Python, is designed to analyze wireless network traffic captured in a PCAP file and count devices that use either globally unique MAC addresses or locally administered MAC addresses. It also performs clustering of devices based on their network capabilities.

## Main ARGO code

- `argo.py`: The main Python script responsible for device counting and clustering based on network traffic in a PCAP file. It can also send the collected data and obtained people count via MQTT, using a JSON payload format, and/or store it in a local/remote MySQL database.
- `models.json`: A JSON file that serves as a device-model database, containing information about different devices and their capabilities.
- `bloomfilter.py`: Python script containing the basic logic about Bloom Filter data structure.
- `bloomfilter_operations.py`: Python script containing the advanced logic about Bloom Filter data structure.

## Utility files

- `blacklist.py`: A utility script that can be used to detect MAC addresses that appear over multiple PCAP captures spaced over time. These addresses are likely due to fixed devices, different than pedestrians/people's Wi-Fi equipped mobile devices, and therefore they should not be counted when ARGO-ToMove is executed in the field. This script also creates a "blacklist.txt" file that contains the list of the MAC addresses observed several time over a given time. This file is read by "argo.py" to exclude them from the clustering and therefore from the count.

## ToMove framework additional files

- Inside `PositioningProvider` you will find a Python code that is able to get the position and navigation data of a vehicle, and send it to an MQTT broker in a JSON payload format. The code is designed to be executed on an on board device connected to a GNSS receiver and running the Linux `gpsd` daemon.
- Inside `VRUWarningSystem` you will find the implementation of an HMI designed to gather, via MQTT, the people counting data produced by "argo.py", and display it on a web-based visualization designed to be displayed both in a fixed position, or on-board of a vehicle. It can also display the distance from a given pedestrian area and show a warning when a vehicle running the script inside "PositioningProvider" is approach such an area. Additionally, it is able to output a CSV log with the last counts received via MQTT, for debugging and data analysis purposes. A sample launch command for the HMI is contained in the script `sample_launch_command.sh`.

## Dependencies

- `datetime`: For time-related functions.
- `sys`: Provides access to some variables used or maintained by the interpreter.
- `argparse`: Allows command-line argument parsing.
- `scapy`: A Python wrapper for the Wireshark packet analyzer.
- `logging`: Used for logging information and errors.
- `json`: For reading a device-model database in JSON format.
- `pandas`: Provides data structures for efficient data manipulation.
- `scipy.spatial`: For calculating distances between data points.
- `sklearn.cluster.DBSCAN`: Implements the DBSCAN clustering algorithm.
- `bitarray`: Used to manage the Bloom Filter bit-array.
- `mmh3`: Provides the logic to use MurMur Hashing for Bloom Filter.
- `math`: Includes some useful math operations.
- `numpy`: For managing multi-dimensional arrays.
- `pymysql`: For storing the collected information in a mySQL database.
- `paho-mqtt`: For data transmission via MQTT.

## Command line arguments

The main `argo.py` code accepts several command-line argument to configure the behaviour of the system. They can be found in the code right after if "`__name__ == "__main__"`" and they can also be displayed when running `argo.py` with the `--help` option.

## A high-level overview of ARGO logic

1. The script starts by parsing the command-line arguments.
2. It reads a device-model database from a JSON file named "models.json."
3. It initializes variables for counting and clustering devices.
4. The script reads and processes packets from a provided PCAP file.
5. It checks the signal power of each packet and discards packets with power below the threshold (the threshold can be use to fine tune, in the field, the counting range).
6. The script extracts relevant fields from each packet, including MAC addresses, capabilities, and other information.
7. It categorizes MAC addresses as globally unique or locally administered.
8. The script collects information about VHT, Extended, and HT capabilities for clustering.
9. It counts devices with globally unique MAC addresses and checks if the minimum percentage condition for clustering is met.
10. If clustering is performed, it uses DBSCAN or OPTICS to cluster devices based on their capabilities. By default, OPTICS is used.
11. The script calculates the average capabilities within each cluster.
12. It estimates the number of devices within each cluster and counts them.
13. The script logs information about the number of devices detected.
14. Finally, the framework can send the obtained information via MQTT using a JSON format and/or to a MySQL database.

## Output

The script generates log information about the devices using globally unique MAC addresses, devices using locally administered MAC addresses, and the total number of detected devices. It also outputs some statistics on the received power of Wi-Fi probes. The obtained information can also be sent via MQTT and/or stored into a local or remote MySQL database.

## Usage

Example usage with data transmission to both MQTT and a MySQL DB running on localhost (127.0.0.1):

```shell
python argo.py --input_file ./example.pcap --db_ip 127.0.0.1 --db_port 6666 --db_user db_username --db_password db_password --db_name ToMove --db_table ARGO-ToMove --enable_db True --mqtt_addr 127.0.0.1:1883 --mqtt_pos 45:7 --mqtt_device_id name_of_counting_device --mqtt_topic peoplecounting-argo --mqtt_duration 60 --mqtt_credentials username#password --enable_mqtt True
```

## Running ARGO-ToMove is a persistent way under Linux

To run ARGO-ToMove in a persistent way to periodically gather people counting data, you should put your device Wi-Fi interface in monitor mode, and then you can rely on a bash script like the following. The script uses `tshark` as a way to get the input PCAPs for ARGO-ToMove.
```
#!/bin/bash

wlan='wlan1' # Insert here the WLAN interface you want to use for getting the Wi-Fi probes for people counting - it must support monitor mode otherwise all counts will likely be zero!

echo device_password | sudo -S ifconfig $wlan down
sleep 2s
echo device_password | sudo -S iwconfig $wlan mode monitor
sleep 2s
echo device_password | sudo -S ifconfig $wlan up
sleep 2s

duration=60 # Capture duration in seconds: data will be aggregated over this interval
folder="/home/pi/ARGO-ToMove" # Folder where argo.py is located
cd $folder

size=0
while true
do
    echo "Capturing ${duration} seconds"
    now=$(date +%d%m%y_%H%M%S)
    filename="Capturing_"$now".pcap"
    sudo -S tshark -i $wlan -a duration:$duration -w WiFi/$filename -F libpcap -f "subtype probe-req" # .pcap files will be saved into a dedicated directory named "WiFi"
    sudo chmod 777 WiFi/$filename
    python argo.py --input_file WiFi/$filename & # Add here also all your other command line parameters (for example to send data via MQTT)
    wait
done

exit 0
```

## Authors

All the authors are or were researchers or master's students at the Politecnico di Torino, Italy.

- **Diego Gasco** - *Researcher and PhD candidate* -
- **Giuseppe Perrone** - *Researcher and PhD candidate* -
- **Riccardo Rusca** - *Former Researcher and post-doc* -
- **Francesco Raviglione** - *Researcher and assistant professor with time contract* -
- **Alex Carluccio** - *Former master's thesis student* -
- **Marco Rapelli** - *Researcher and assistant professor with time contract* -

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. The MIT License is a permissive open-source license that allows you to use, modify, and distribute this code, subject to certain conditions.

### MIT License Summary

- **Permissions:** This license allows you to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software.
- **Conditions:** You must include the original copyright notice and the MIT License text in all copies or substantial portions of the software.
- **Liability:** The software is provided "as is," and the authors are not liable for any damages or issues arising from the use of the software.

For the full text of the MIT License, please see the [LICENSE](LICENSE) file in this project.


