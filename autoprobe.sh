#! /bin/bash

echo -e "\e[1m\e[33m---------------------------------------------------------------------\e[0m\e[0m"
echo -e "\e[1m \e[40m

   _____          __        __________              ___.           
  /  _  \  __ ___/  |_  ____\______   \_______  ____\_ |__   ____  
 /  /_\  \|  |  \   __\/  _ \|     ___/\_  __ \/  _ \| __ \_/ __ \ 
/    |    \  |  /|  | (  <_> )    |     |  | \(  <_> ) \_\ \  ___/ 
\____|__  /____/ |__|  \____/|____|     |__|   \____/|___  /\___  >
        \/                                               \/     \/ 
\e[0m \e[0m"
echo -e "\e[1m\e[33m---------------------------------------------------------------------\e[0m\e[0m"


echo -e "\e[1m \e[41m usage: autoprobe.sh <memory image> \e[0m \e[0m"

echo ""
# Display menu options
while true; do
    echo -e "\e[1m \e[33mMenu Options:\e[0m \e[0m"
    echo -e "\e[92m1. Process Investigation\e[0m"
    echo -e "\e[92m2. Exit\e[0m"

    read -p "Enter your choice (1 or 2): " choice

    case $choice in
        1)
            echo ""
            echo -e "\e[92mProcess Investigation:\e[0m"
            echo ""
            echo -e "\e[94m----------------------------\e[0m"
            echo -e "\e[1m \e[40mAutoprobe Methodology\e[0m \e[0m"
            echo -e "\e[94m----------------------------\e[0m"
            echo ""
            echo -e "\e[32m1. Identifying the image\e[0m \e[0m"
            echo -e "-------------------------------------------------"
            echo -e "\e[33m2. Listing processes using pslist\e[0m \e[0m"
            echo -e "\e[33m3. Listing processes using psscan\e[0m \e[0m"
            echo -e "\e[33m4. listing processes using psxview\e[0m \e[0m"
            echo -e "---------------------------------------------------"
            echo -e "\e[91m5. Comparing the results to identify suspicious processes \e[0m \e[0m"
            echo -e "\e[91m6. Filtering and categorizing processes (singleton, windows core, non-core)\e[0m \e[0m"
            echo -e "--------------------------------------------------------------------------------"
            echo -e "\e[34m7. Inspecting handles for selected processes\e[0m \e[0m"
            echo -e "\e[34m8.inspecting Registry keys\e[0m"
            echo -e "\e[34m9.process dump\e[0m"
            echo -e "\e[34m10.analysing loaded dlls\e[0m"
            echo -e "\e[34m11.taking dlldump\e[0m"
            echo -e "\e[34m12.analyzing  dumped executables and dlls from virustotal\e[0m"

            echo ""
            
            read -p "press Enter to continue..."

            # Run the process investigation section of the script
            # Add your existing code for process investigation here

            echo ""



# Function to delete existing results and exports folders
delete_existing_folders() {
    if [ -d "results" ]; then
        rm -r results
    fi
    if [ -d "exports" ]; then
        rm -r dump
    fi
}

# Check if results and exports folders exist
if [ -d "results" ] || [ -d "exports" ]; then
    
    delete_existing_folders
fi
echo ""


# Create new results and exports folders
mkdir results
mkdir dump




# echo ""





echo -e "\e[34m------------------------------------------------------------------------------\e[0m"
echo -e "\e[33m \e[40mscanning results will be saved in the /results folder \e[0m\e[0m"
echo -e "\e[33m \e[40mfiles extracted from memory will be saved to the /exports folder \e[0m\e[0m"
echo -e "\e[34m------------------------------------------------------------------------------------\e[0m"
echo ""


res=results
dmp=dump

# echo ""


# echo ""

date > $res/imageinfo_"$1"\_.txt
volatility -f $1 imageinfo | tee -a $res\imageinfo_"$1"\_.txt

echo ""
echo -e " \e[1m \e[41m enter the KDBG signature to use for this memory image,example win2000xbbf1 \e[0m \e["

read kdbg

echo ""

echo -e "\e[33m \e[1m \e[40m the operating system profile selected is : --profile=\e[0m\e[0m\e[0m"$kdbg

exec 2>/dev/null
echo ""

# automating pslist and psscan

echo -e "\e[1mʟɪsᴛɪɴɢ ᴘʀᴏᴄᴇssᴇs \e[41mPSLIST\e[0m\e[0m"



echo -e "\e[33m------------------------------------------------------------------------------------------\e[0m"
echo -e "\e[94m \e[40mThe pslist module list the processes from memory like the task manager does, 
so it will not be able to find terminated processes and processes hidden by rootkits..\e[0m\e[0m"

echo -e "\e[94m \e[40mThe windows kernel uses the EPROCESS data structure to describe each running process
pslist traverses the list of active process structures that the Windows kernel maintains.\e[0m\e[0m"
echo -e "\e[33m------------------------------------------------------------------------------------------------\e[0m"
echo -e "\e[41m More on: \e[0m"
echo -e "\e[92m http://akovid.blogspot.com/2014/02/difference-between-pslist-and-psscan.html\e[0m"

echo ""

volatility -f $1 --profile=$kdbg pslist | tee -a $res/pslist_"$1"\_.txt  


echo ""

echo -e  "\e[41m Now Let's look at the parent child relationships of the above listed processes..\e[0m"





# Prompt user to press Enter to continue

echo -e "\e[94m Press enter to continue\e[0m"

read -p "Press Enter to continue..."

volatility -f $1 --profile=$kdbg pstree --output=dot --output-file=$res/pstree_"$1"\_.dot

xdot $res/pstree_"$1"\_.dot



echo ""

echo -e "\e[1mʟɪsᴛɪɴɢ ᴘʀᴏᴄᴇssᴇs \e[41mPSSCAN\e[0m\e[0m"

echo -e "\e[34m------------------------------------------------------------------------------\e[0m"
echo -e " \e[33m \e[40mThe psscan module scans the whole memory for process structures\e[0m"
echo -e " \e[33m \e[40mand is able to find both hidden an terminated processes.\e[0m"
echo -e "\e[34m------------------------------------------------------------------------------\e[0m"
volatility -f $1 --profile=$kdbg psscan | tee -a $res/psscan_"$1"\_.txt

echo ""

echo -e "\e[31m Now Let's look at the parent child relationship from the above psscan result \e[0m "

# Prompt user to press Enter to continue

echo -e "\e[94m Press enter to continue\e[0m"

read -p "Press Enter to continue..."


volatility -f $1 --profile=$kdbg psscan --output=dot --output-file=$res/psscan_"$1"\_.dot

xdot $res/psscan_"$1"\_.dot



echo -e "\e[34m------------------------------------------------------------------\e[0m"
echo -e "\e[41mBy comparing the results from both pslist and psscan\e[0m" 
echo -e "\e[40mwe can see which processes where actually hidden or terminated\e[0m"
echo -e "\e[34m-------------------------------------------------------------------\e[0m"

cat $res/psscan_"$1"\_.txt | grep -E --color $(cat $res/pslist_"$1"\_.txt $res/psscan_"$1"\_.txt | cut -d " " -f2 | sort | uniq -c | grep "1" | cut -d " " -f8 | grep -v "-" | tr '\n' '|')

echo ""

echo -e "\e[40mthe process name in \e[41mRED\e[0m] shows that these processes are not present in the pslist result\e[0m"

echo ""
echo -e "\e[34m-------------------------------------------------------------------------\e[0m"
echo -e "\e[33mpsscan plugin relies on proc tag which is a great way to identify
processes.But it turns out that if an attacker can somehow install a
kernel driver on a system then they can modify the proc tag for their purposes..\e[0m"
echo -e "\e[34m-------------------------------------------------------------------------\e[0m"
echo ""
echo -e "\e[33m-------------------------------------------------------------------------\e[0m"
echo -e "\e[94mUsing the Volatility psxview plugin, 
we can see if the process appears in pslist and psscan plugin by the boolean value True. 
 A False within the column indicates that the process is not found in that area.
This allows the analyst to review the list and determine if there’s a legitimate reason for that.\e[0m"
echo -e "\e[33m--------------------------------------------------------------------------------\e[0m"
echo ""

volatility -f $1 --profile=$kdbg psxview | tee -a $res/psxview_"$$1"\_.txt

echo ""
echo "-----------------------------------------------------------------------"
echo -e "\e[92mresults of psxview after applying -R tag for rules\e[0m"
echo "---------------------------------------------------------------------"
echo ""
volatility -f $1 --profile=$kdbg psxview -R | tee -a $res/psxviewrules_"$1"\_.txt 


echo ""

echo -e "\e[33m=======================(SINGLETON PROCESSES)===========================\e[0m"

█echo""

echo "-----------------------------------------------------------------------"
echo -e "\e[94m singleton processes are programs or services on acomputer
that are designed to run only one instance at a time.\e[0m"
echo "----------------------------------------------------------------------------"

echo ""

echo -e "\e[94mOffset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          \e[0m"

grep -E -i "(system|winit|lsass|lsm|services|smss|logonUI|rdpclip|wisptis|WaaSMediSvc)" $res/pslist_$1\_.txt > $res/pslist_singletons_$1\_.txt

cat $res/pslist_singletons_$1\_.txt

echo ""

echo -e "\e[34m=======================(\e[33mWINDOWS CORE PROCESSES\e[0m)===========================\e[0m"

echo "------------------------------------------------------------------------"
echo -e "\e[35mWindows core processes are essential programs or services 
that are fundamental to the operation of the Windows operating system...\e[0m"
echo "---------------------------------------------------------------------------"

echo ""

grep -E -i "(System Idle Process|System|smss|csrss|wininit|services|lsass|svchost|explorer|winlogon|spoolsv|lsass|dllhost|dwm|taskhost|spoolsv|lsaiso|SearchIndexer|RuntimeBroker|SecurityHealthService|NisSrv|WmiPrvSE|PresentationFontCache|csrss|winlogon|LogonUI|fontdrvhost|WUDFHost|WmiApSrv|wininit|conhost|taskhostw|rdpclip|wisptis|WaaSMedicSvc)" $res/pslist_$1\_.txt > $res/pslist_windowscore_$1\_.txt


echo -e "\e[94mOffset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          \e[0m"

cat $res/pslist_windowscore_$1\_.txt

echo ""


echo -e "\e[34m=======================(\e[33mNON CORE PROCESSES[PSLIST]\e[0m)===========================\e[0m"

echo ""
echo "-----------------------------------------------------------------------"
echo -e "\e[93m These  are typically user-installed applications, 
background services, or utilities that provide additional functionalities 
beyond what the operating system offers by default\e[0m"
echo "---------------------------------------------------------------------------"
echo ""
grep -E -i -v "(System Idle Process|System|smss|csrss|wininit|services|lsass|svchost|explorer|winlogon|spoolsv|lsass|dllhost|dwm|taskhost|spoolsv|lsaiso|SearchIndexer|RuntimeBroker|SecurityHealthService|NisSrv|WmiPrvSE|PresentationFontCache|csrss|winlogon|LogonUI|fontdrvhost|WUDFHost|WmiApSrv|wininit|conhost|taskhostw|rdpclip|wisptis|WaaSMedicSvc)" $res/pslist_$1\_.txt > $res/pslist_Noncore_$1\_.txt
echo ""

cat $res/pslist_Noncore_$1\_.tx

echo -e "\e[34m=======================(\e[33mNON CORE PROCESSES[PSSCAN]\e[0m)===========================\e[0m"

echo "--------------------------------------------------------------------------------------------------------------"
echo -e "\e[33m On analysing the results from psscan and pslist we can find the processes which are terminated\e[0m"
echo "--------------------------------------------------------------------------------------------------------------------"
echo ""
grep -E -i -v "(System Idle Process|System|smss|csrss|wininit|services|lsass|svchost|explorer|winlogon|spoolsv|lsass|dllhost|dwm|taskhost|spoolsv|lsaiso|SearchIndexer|RuntimeBroker|SecurityHealthService|NisSrv|WmiPrvSE|PresentationFontCache|csrss|winlogon|LogonUI|fontdrvhost|WUDFHost|WmiApSrv|wininit|conhost|taskhostw|rdpclip|wisptis|WaaSMedicSvc)" $res/psscan_$1\_.txt > $res/psscan_Noncore_$1\_.txt


cat $res/psscan_Noncore_$1\_.txt


echo -e "\e[102m*****************************************************************************************************\e[0m"
echo "" 
# Inform the user that all processes have been listed
echo "-------------------------------------------------------------------------------------"
echo -e "\e[94mAll processes have been listed. Now, let's look at the handles.\e[0m"
echo "--------------------------------------------------------------------------------------"

while true; do
    # Prompt the user to enter the PID for the specific process they want to examine handles for
    echo -e "\e[92mEnter the PID of the process for which you want to examine handles:\e[0m"

    read -p "Enter the PID of the process for which you want to examine handles: " pid

    # Run Volatility's handles plugin to gather information about objects and handles for the specified process
    echo -e "\e[92mAnalyzing objects and handles for process $pid\e[0m"
    volatility -f $1 --profile=$kdbg handles -p $pid | tee -a results/handles_$pid.txt

    echo ""
    echo -e "\e[33mAnalysis completed for process $pid\e[0m"
    echo ""

    # Ask the user if they want to analyze handles for another process
    echo -e "\e[94mDo you want to analyze handles for another process? (yes/no): \e[0m"

    read -p "Do you want to analyze handles for another process? (yes/no): " choice

    if [ "$choice" != "yes" ]; then
            break
        
    fi
done

echo -e "\e[96mHandle analysis completed for the processes.\e[0m"


# Function to examine common startup registry keys
examine_registry_keys() {
    echo ""
    echo -e "\e[1m\e[41m=================Examining common startup registry keys:======================\e[0m"
    echo ""
    
    # Define an array of common startup registry keys
    startup_keys=(


         # HKEY_LOCAL_MACHINE (HKLM)
        "Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices"
        "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
        
        # HKEY_CURRENT_USER (HKCU)
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load"
        "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run"
        
        # HKEY_USERS (HKU)
        "HKU.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    # Iterate through the array of startup keys and examine each one
    for key in "${startup_keys[@]}"; do
        echo -e "\e[34mExamining registry key:\e[0m \e[33m$key\e[0m"
        echo ""
        volatility -f "$1" --profile="$kdbg" printkey -K "$key" | tee -a "$res/registry_$key_$1.txt"
        echo ""
    done

    echo -e "\e[94mRegistry key examination completed.\e[0m"
}

# Call the function to examine common startup registry keys
examine_registry_keys "$1"
echo ""
echo -e "\e[34mThere are limitations on examining registry key from memory forensics\e[0m"

echo -e "------------------------------------------------------------------------------------------"
echo -e "\e[34mThe operating system allocates registry-related structures from the paged pool. 
The paged pool is a portion of virtual memory that can be paged out to the hard disk when not in active use.\e[0m"
echo -e "-----------------------------------------------------------------------------------------------"



echo -e "--------------------------------------------------------------------------------------------------"
echo -e "\e[33mSince the registry data can be paged out, a memory dump might not contain a complete or accurate 
representation of the registry keys at the time of the capture. 
Analysts might only see partial data, leading to incomplete or misleading conclusions\e[0m"
echo -e "--------------------------------------------------------------------------------------------------"




while true; do
    # Prompt user to enter the process IDs for dumping
    echo -e "Enter the PIDs of the processes you want to dump (separated by spaces):"
    read -p "Enter the PIDs of the processes you want to dump (separated by spaces): " -a pids

    # Iterate through each entered PID and dump the process
    for pid in "${pids[@]}"; do
        echo -e "\e[92mDumping process with PID $pid\e[0m"
        volatility -f $1 --profile=$kdbg procdump -p $pid -D $dmp
        echo -e "\e[92mProcess dump completed for PID $pid. Dumps are saved in the dump folder.\e[0m"
    done

    # Ask the user if they want to dump another set of processes
    echo -e "\e[33mDo you want to dump another set of processes? (yes/no):\e[0m"
    read -p "Do you want to dump another set of processes? (yes/no): " choice
    if [ "$choice" != "yes" ]; then
        break
    fi
done


while true; do
    # Prompt the user to enter the PID for the specific process they want to examine handles for
    echo -e "\e[92mEnter the PID of the process for  examining dlls:\e[0m"

    read -p "Enter the PID of the process for examining dlls: " pid

    # Run Volatility's dlllist plugin to gather information about dlls loaded  for the specified process
    echo -e "\e[92mAnalyzing loaded dlls for process $pid\e[0m"
    volatility -f $1 --profile=$kdbg dlllist -p $pid | tee -a results/dlls_$pid.txt

    echo ""
    echo -e "\e[33mAnalysis completed for process $pid\e[0m"
    echo ""

    # Ask the user if they want to analyze dlls for another process
    echo -e "\e[94mDo you want to analyze dlls for another process? (yes/no): \e[0m"

    read -p "Do you want to analyze dlls for another process? (yes/no): " choice

    if [ "$choice" != "yes" ]; then
            break
        
    fi
done




echo -e "Analysing dumped dlls and executables through virustotal"

process_hash() {
    local hash_value=$1
    json_data=$(vt file $hash_value --format=json)
     echo "$json_data" | jq '.[] as $parent| $parent.last_analysis_results | map_values(select(.category == "malicious").category), $parent.last_analysis_stats'
}

# change the path from * to dump/*
readarray -t datas < <(sha256sum dump/*)

for data in "${datas[@]}"; do
    hash_value=$(echo $data | awk '{print $1}')
    file_name=$(echo $data | awk '{print $2}'|cut -d "/" -f2 )
    printf "===============[ $file_name ]============\n"
    process_hash $hash_value 
done



            ;;
        2)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done
