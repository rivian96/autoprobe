# AutoProbe: Memory Forensics Automation Script
AutoProbe is a Bash script designed to automate the process of investigating memory dumps for suspicious processes. The script utilizes the Volatility framework to perform a series of checks and analyses, making it easier for forensic analysts to identify potentially malicious activities within memory images.

![Screenshot (91)](https://github.com/user-attachments/assets/9f4c6614-d388-4901-90f9-2c18f22619f6)


## Features
![Screenshot (93)](https://github.com/user-attachments/assets/b24da430-eb60-42d8-9cef-37c0ed64010b)

- Automatically identifies the memory image
- Lists processes using `pslist`, `psscan`, and `psxview`
- Compares results to identify hidden or terminated processes
- Categorizes processes (singleton, Windows core, non-core)
- Inspects handles, registry keys, and DLLs for selected processes
- Dumps processes and analyzes loaded DLLs
- uses virustotal for scanning dumped processes hashes



 ## ** PREREQUISITES **

## Installing Volatility Standalone on Linux

To install the standalone version of Volatility on Linux, follow these steps:

1. ## **Download the Standalone File**

   Go to the [Volatility 2.6.1 release page](https://github.com/volatilityfoundation/volatility/releases/tag/2.6.1) and download the standalone file for Linux.

   ![Screenshot (85)](https://github.com/user-attachments/assets/b99a52ba-ba02-40af-b330-426adf1a360d)

2. ## **Unzip the File**

  ** Unzip the downloaded file. You can use the `unzip` command in the terminal:**

   ![Screenshot (86)](https://github.com/user-attachments/assets/dcbb1110-ed65-4c57-aaba-0360d6b742fe)

`
  
3. ## **Rename the Standalone File**
   ![Screenshot (87)](https://github.com/user-attachments/assets/836b0240-ec91-428b-9300-7825bc8c8da7)


4. ## **move the file to /usr/bin**
   ![Screenshot (90)](https://github.com/user-attachments/assets/78689c13-ebaa-427d-9cc5-34621fb473f8)


5.  ## `xdot` must be installed for visualizing process trees**

   ![Screenshot (89)](https://github.com/user-attachments/assets/242bc6df-62ca-4ca9-bdb3-e5b426d4d0d5)




## Usage

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/autoprobe.git
    cd autoprobe
    ```

2. Make the script executable:
    ```bash
    chmod +x autoprobe.sh
    ```

3. Run the script with a memory image:
    ```bash
    ./autoprobe.sh <memory image>
    ```

    Replace `<memory image>` with the path to your memory dump file.

## Menu Options

Upon running the script, you'll be presented with the following menu options:

1. **Process Investigation**
    - Lists processes using `pslist`, `psscan`, and `psxview`
    - Identifies suspicious processes by comparing results
    - Categorizes processes as singleton, Windows core, or non-core
    - Inspects handles and registry keys for selected processes
    - Dumps processes and analyzes loaded DLLs
    - scans dumped files hashses from virustotal

2. **Exit**
    - Exits the script

## Example Output

The script saves results and dumped files in the following directories:
- `results`: Contains scan results and analysis output
- `dump`: Contains dumped processes and DLLs

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. For major changes, please open an issue to discuss what you would like to change.

## License

This project is licensed under the MIT License. 



