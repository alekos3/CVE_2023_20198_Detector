# CVE_2023_20198_Detector

This script can identify if Cisco IOS XE devices are vulnerable to CVE-2023-20198. The script takes as input a csv file with all the device IP addresses that you want to check. By default the script looks for a file named "devices.csv"; you can name the file something different but then you must pass the "--devices" argument to the script followed by the file name.

The script is threaded and will analyze 10 devices in parallel at a time; DO NOT increase the threads unless you are certain of what you are doing. The script is READ ONLY and will not make any configuration changes to any devices it ssh's into. Use at your own risk.

The script generates a csv report in the current it's being executed from with the results for any given device. If you see anything other than "NO" in the vulnerabilites found column then that means the device is vulnerable.

## Usage/Examples

```bash
python3 CVE_2023_20198_detector.py --devices ios_xe_devices.csv

python3 CVE_2023_20198_detector.py
```


