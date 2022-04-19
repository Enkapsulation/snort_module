# Heuristic module

## Instalation

1. You have to clone repository or download code to your machine
2. Go to source directory (e.q snort_module)
3. To compile and install:
	* run in terminal: ./configure_cmake.sh --prefix=/usr/local
	* cd build
	* make -j<number_of_cores>
	* sudo make install -j<number_of_cores>

### Run heuristic module

To run module, use snort command line parameter: `--plugin-path=` 

* `sudo snort --plugin-path /usr/local/lib/snort/plugins/extra/ -c snort_config.lua -i wlan0  -A alert_full`

## File with suspicious IP address

File with suspicious IP address contain suspicious IP address and flags. File have to be saved in file with CSV format. 

``

1. Suspicious IP address
2. Dangerous flag
3. Attack type
4. Range flag
5. Access flag
6. Availability flag
7. Counter 
8. Packet entropy
### How the packet value is count?


### Suspicious IP address
### Dangerous flag
### Attack type
### Access flag
### Availability flag
### Counter
### Packet entropy
