import os, io, shutil, threading, subprocess, platform, time, argparse
import requests, pandas as pd, pefile, hashlib, re, json, msilib, bs4
from datetime import datetime, timezone

#--------------------------------------------------------------#
            #- folder download / unquarantine -# 
            
     
     

#------------------ end of folder download ------------------#
                       #- PE analysis -#                 
                    
                
            
     
def valid_sample(file, filePath):
    extensionDict = {
        "exe": b'\x4D\x5A',
        "dll": b'\x4D\x5A',
        "bin": b'\x4D\x5A',
        "elf": b'\x7F\x45\x4C\x46',
    }

    extension = file.lower().split('.')[-1]
    if extension in extensionDict:
        signature = extensionDict[extension]
        with open(filePath, 'rb') as file:
            header = file.read(len(signature))
            return header == signature

    return False
    
def extract_strings(filename):
    strings = []
    with open(filename, 'rb') as file:
        # read all binary data
        binData = file.read()
        
        # regex for ASCII strings >= 4 characters
        regex = b'[ -~]{4,}'
        matches = re.findall(regex, binData)
        
        # decoding strings to unicode
        for match in matches:
            try:
                string = match.decode('utf-8')
                strings.append(string)
            except UnicodeDecodeError:
                pass
    
    return strings

def rename_keys(data, oldKey, newKey):
    # retargeting function
    if isinstance(data, dict):
        for key in list(data.keys()):
            if key == oldKey:
                data[newKey] = data.pop(key)
            else:
                rename_keys(data[key], oldKey, newKey)
    elif isinstance(data, list):
        for item in data:
            rename_keys(item, oldKey, newKey)

def remove_keys(data, keys):
    # key walk-delete function
    if isinstance(d, dict):
        for key in list(d.keys()):
            if key in keys:
                del d[key]
                keys.remove(key)
            else:
                remove_keys(d[key], keys)
    elif isinstance(d, list):
        for item in d:
            remove_keys(item, keys)

# Mandiant CAPA analysis
def analyze_executable(filePath, outFile1):
    try:
        basePath = getattr(sys, '_MEIPASS', os.path.abspath("."))
        capaPath = os.path.join(basePath, "capa.exe")
        rulesPath = os.path.join(basePath, "sigs")
        # running as a subprocess to capture stdout correctly
        # print(rules_folder)
        command = [
            capaPath,
            '--quiet',
            '--json', filePath,
            '--rules',rulesPath
        ]
        if platform.system().lower() == "windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            capaThread = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, startupinfo=startupinfo)
        else:
            capaThread = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        stdout, stderr = capaThread.communicate()

        if capaThread.returncode != 0:
            # print(f"Error analyzing {filePath}: {stderr}")
            return

        result = json.loads(stdout)

        keys = ['timestamp', 'version', 'argv', 'extractor', 'authors', 'references', 'examples', 'description', 'maec', 'rules']
        #remove_keys(result, keys)
        
        if 'meta' in result:
            del result['meta']
        rename_keys(result, 'rules', 'Behaviors')

        # grab strings
        binStrings = extract_strings(filePath)
        result['Strings'] = binStrings

        # write to JSON file for popup pane pretty printin'
        with open(outFile1, 'w') as f:
            json.dump(result, f, indent=4)

    except Exception as e:
        # print(f"Error analyzing {filePath}: {e}")
        pass
        

# constants for PE section characteristics
SECTION_CHARACTERISTICS = {
    0x00000020: "Code Section",
    0x00000040: "Initialized Data Section",
    0x00000080: "Uninitialized Data Section",
    0x20000000: "Executable Section",
    0x40000000: "Readable Section",
    0x80000000: "Writable Section",
    0x02000000: "Discardable Section"
}

# constants for PE header characteristics
HEADER_CHARACTERISTICS = {
    0x0001: "Relocations Stripped: indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address",
    0x0002: "Executable Image: indicates that the image file is valid and can be run",
    0x0004: "Line Numbers Stripped: COFF line numbers have been removed [deprecated]",
    0x0008: "Local Symbols Stripped: COFF symbol table entries for local symbols have been removed [deprecated]",
    0x0010: "Aggressive Trim Working Set: aggressively trim working set [deprecated for Windows 2000 and later]",
    0x0020: "Large Address Aware: can handle greater than 2gb addresses",
    0x0040: "Reserved",
    0x0080: "32-bit Machine: little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory [deprecated]",
    0x0100: "32-bit Machine: image is based on a 32-bit word architecture",
    0x0200: "Debug Stripped: debugging information is removed from the image",
    0x0400: "Removable Run from Swap: if the image is on removable media, fully load it and copy it to the swap file",
    0x0800: "Net Run from Swap: if the image is on network media, fully load it and copy it to the swap file",
    0x1000: "System File: image is a sys file not a user program",
    0x2000: "DLL File: image is a dynamic-link library - considered executable files for almost all purposes, although they cannot be directly run",
    0x4000: "Up System Only: file should be run only on a uniprocessor machine",
    0x8000: "Bytes Reversed: big endian: the MSB precedes the LSB in memory [deprecated]"
}

# constants PE DLL characteristics
DLL_CHARACTERISTICS = {
    0x0001: "Reserved",
    0x0002: "Reserved",
    0x0004: "Reserved",
    0x0008: "Reserved",
    0x0020: "High Entropy Virtual Addresses: image can handle a high entropy 64-bit virtual address space",
    0x0040: "Dynamic Base: dll can move at load time",
    0x0080: "Force Integrity Checks",
    0x0100: "NX Compatible",
    0x0200: "No Isolation: isolation aware but do not isolate",
    0x0400: "No Structured Exception Handling: does not use structured exception (SE) handling. No SE handler may be called in this image",
    0x0800: "Do Not Bind Image",
    0x1000: "App Container: image must execute in an AppContainer",
    0x2000: "WDM Driver",
    0x4000: "Guard CF: image supports Control Flow Guard",
    0x8000: "Terminal Server Aware"
}

def get_section_characteristics(characteristics):
    charData = []
    for flag, description in SECTION_CHARACTERISTICS.items():
        if characteristics & flag:
            charData.append(description)
            
    return ', '.join(charData)
    
def get_file_header_characteristics(characteristics):
    charData = []
    for flag, description in HEADER_CHARACTERISTICS.items():
        if characteristics & flag:
            charData.append(description)
            
    return charData

def get_dll_characteristics(characteristics):
    charData = []
    for flag, description in DLL_CHARACTERISTICS.items():
        if characteristics & flag:
            charData.append(description)
            
    return charData
    
def draw_bar_graph(sectionName, size, maxSize, maxSectionWidth=10, maxWidth=86):
    barLength = int(size / maxSize * maxWidth)
    bar = "[" + "|" * barLength + " " * (maxWidth - barLength) + "]"
    spacing = maxSectionWidth - len(sectionName)
    colon = " " * spacing
    
    return "{}{}".format(colon, bar) 

def detect_obfuscation(code):
    markers = [
        "",
        "",
    ]

    for marker in markers:
        if marker in code:
            return True

    return False    
    
def detect_packer(filePath):
    packers = {
        "UPX": b"UPX!",
        "PECompact": b"PECOMPACT",
        "Themida": [b"THEMIDA_V001", b"THEMIDA_V002", b"THEMIDA_V003", b"THEMIDA_V004", b"THEMIDA_V005"],
        "Enigma": b"ENIGMA",

    }

    # needs work
    with open(filePath, "rb") as file:
        content = file.read()

    detectedPacker = None
    for packer, indicators in packers.items():
        for indicator in indicators:
            if indicator in content:
                detectedPacker = packer
                break
        if detectedPacker:
            break

    return detectedPacker
    
# calculate md5, sha1/256 hashes
def calculate_hashes(filePath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filePath, "rb") as file:
        while chunk := file.read(4096):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

# get compiler architecture
def get_architecture(pe):
    machineType = pe.FILE_HEADER.Machine
    if machineType == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        return "x86 (32-bit)"
    elif machineType == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        return "x64 (64-bit)"
    return "Unknown"

# get compilation time
def get_compilation_time(pe):
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
    except:
        return 'Not found'

    if timestamp == 0:
        return 'Not Found'

    timestamp_fmt = datetime.fromtimestamp(int(timestamp), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    if timestamp < 946692000:
        suspicious = '[Suspicious] Old timestamp'
    elif timestamp > int(time.time()):
        suspicious = '[Suspicious] Future timestamp'
    else:
        suspicious = ''

    answer = '%s %s' % (timestamp_fmt, suspicious)
    return answer

# get PE format
def get_pe_format(pe):
    if pe.is_dll():
        return "Dynamic Link Library"
    elif pe.is_driver():
        return "Driver"
    elif pe.is_exe():
        return "Executable"
    return "Unknown"

# reference malAPI.io to get suspicious APIs    
def malAPI_Check(api):
    try:
        request = requests.get("https://malapi.io/winapi/" + api)
        request.raise_for_status()
        responseData = bs4.BeautifulSoup(request.text, 'html.parser')

        if "404 Not Found" in responseData.getText():
            return None

        details = responseData.select('.detail-container .content')
        apiDesc = details[1].getText().lstrip().rstrip()
        apiDesc.replace(api, '')
        apiAttacks = " ".join(details[3].getText().lstrip().rstrip().split())
        susAPI = api + ' - ' + apiDesc + '    Type:' + apiAttacks
        return susAPI
    
    except requests.exceptions.RequestException as e:
        # print("Error: API DOC request failed. No internet?")
        return None
        
# get interesting strings                
def get_interesting_strings(strings):
    urlRegex = r'(?i)\b((?:http[s]?:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>"]+|\(([^\s()<>"]+|(\([^\s()<>"]+\)))*\))+(?:\(([^\s()<>"]+|(\([^\s()<>"]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\'"]))'

    fileRegex = r'\b([\w,%-.]+\.[A-Za-z]{3,4})\b'
    emailRegex = r'((?:(?:[A-Za-z0-9]+_+)|(?:[A-Za-z0-9]+\-+)|(?:[A-Za-z0-9]+\.+)|(?:[A-Za-z0-9]+\++))*[A-Za-z0-9]+@(?:(?:\w+\-+)|(?:\w+\.))*\w{1,63}\.[a-zA-Z]{2,6})'
    ipRegex = r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    plainRegex = r'\b[A-Za-z0-9_]+\b'

    results = {
        'URLs': [],
        'Files': [],
        'Emails': [],
        'IPs': []
    }


    if isinstance(strings, str):
            inString = strings
    elif isinstance(strings, list):
            inString = ' '.join(strings)
    else:
            inString = str(strings)

    urls = re.compile(urlRegex, re.IGNORECASE)
    files = re.compile(fileRegex, re.IGNORECASE)
    emails = re.compile(emailRegex, re.IGNORECASE)
    ips = re.compile(ipRegex, re.IGNORECASE)
    plainText = re.compile(plainRegex)

    results['URLs'] = urls.findall(inString)
    results['Files'] = files.findall(inString)
    results['Emails'] = emails.findall(inString)
    results['IPs'] = ips.findall(inString)
    # results['Plain Text'] = plainText.findall(inString)

    return results

     
    
# maguna analysis
def extract_pe_info(pePath, outFile1, silent=False):
    try:
        # initializing the json dictionary        
        peInfo = {       
            "Report": {},
            "Basic Info": {},
            "Section Info": [],
            "Import Table": [],
            "Exported Functions": [],
            "Memory Graphs": {
                "Raw Size": {},
                "Virtual Size": {}
            }
        }            

        # get the file size & open it
        fileSize = os.path.getsize(pePath)
        fileSizeMb = fileSize / (1024 * 1024)
        pe = pefile.PE(pePath)
        
        md5, sha1, sha256 = calculate_hashes(pePath)
        compilerArchitecture = get_architecture(pe)
        compilationTime = get_compilation_time(pe)
        peFormat = get_pe_format(pe)        


        # basic extraction
        headerCharacteristics = pe.FILE_HEADER.Characteristics
        headerCharacteristicsList = get_file_header_characteristics(headerCharacteristics)
        dllCharacteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        dllCharacteristicsList = get_dll_characteristics(dllCharacteristics)
        basicInfo = {
            "PE Format": peFormat,          
            "Compiler Architecture": compilerArchitecture,
            "Compilation Time": compilationTime,      
            "File Size": "{} bytes / {:.2f} MB".format(fileSize, fileSizeMb),
            "MD5 Hash": md5,
            "SHA1 Hash": sha1,
            "SHA256 Hash": sha256,
            "Image Base": "0x{:08X}".format(pe.OPTIONAL_HEADER.ImageBase),
            "Entry Point": "0x{:08X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "File Alignment": "0x{:08X}".format(pe.OPTIONAL_HEADER.FileAlignment),
            "Section Alignment": "0x{:08X}".format(pe.OPTIONAL_HEADER.SectionAlignment),
            "Number Of Sections": [pe.FILE_HEADER.NumberOfSections],
            "File Header Characteristics": headerCharacteristicsList,
            "DLL Characteristics": dllCharacteristicsList
        }
        peInfo["Basic Info"] = basicInfo

        # check for an invalid checksum
        if pe.OPTIONAL_HEADER.CheckSum == 0:
            peInfo["Report"]["Invalid checksum"] = {
                "|": "PE file checksum is required for drivers, boot-time DLLs, and other DLLs loaded into secure system processes. Malware often ingores this value or sets it to zero"
            }

        # section header extraction
        sectionInfo = {}
        imgBase = pe.OPTIONAL_HEADER.ImageBase
        for section in pe.sections:
            sectionName = section.Name.decode("utf-8").strip('\x00')
            virtSize = "0x{:08X}".format(section.Misc_VirtualSize)
            rawSize = "0x{:08X}".format(section.SizeOfRawData)
            virtAddress = "0x{:08X}".format(section.VirtualAddress)
            rawAddress = "0x{:08X}".format(section.PointerToRawData)
            characteristics = get_section_characteristics(section.Characteristics)
            entropy = section.get_entropy()
            
            mappedAddress = "0x{:08X}".format(imgBase + section.VirtualAddress)
            
            # check for relocation data
            if section.PointerToRelocations and section.NumberOfRelocations:
                relocInfo = {
                    "PointerToRelocations": "0x{:08X}".format(section.PointerToRelocations),
                    "NumberOfRelocations": section.NumberOfRelocations,
                }
            else:
                relocInfo = None            
            
            sectionInfo[sectionName] = {
                "Raw Size": rawSize,
                "Virtual Size": virtSize,
                "Raw Address": rawAddress,
                "Virtual Address": virtAddress,
                "Mapped Address": mappedAddress,
                "Relocation Info": relocInfo,
                "Characteristics": characteristics,
                "Entropy": entropy
            }
            
            if relocInfo is None and "Relocation Info" in sectionInfo[sectionName]:
                del sectionInfo[sectionName]["Relocation Info"]
            
            # check for section size discrepancies in raw / virtual data
            for sectionName, sectionData in sectionInfo.items():
                virtSize = int(sectionData["Virtual Size"], 16)
                rawSize = int(sectionData["Raw Size"], 16)
                if abs(virtSize - rawSize) >= 0x10000:
                    peInfo["Report"]["Contains sections with size discrepancies"] = {
                        "|": "Sections with a large discrepancy between raw and virtual sizes may indicate a packed or obfuscated PE file"
                    }

            # check for sections with zero size
            for sectionName, sectionData in sectionInfo.items():
                rawSize = int(sectionData["Raw Size"], 16)
                if rawSize == 0:
                    peInfo["Report"]["Contains sections with zero size"] = {
                        "|": "Sections with zero size may indicate a packed or obfuscated PE file"
                    }

            # check for sections with high entropy
            highEntropyWarning = False
            for sectionName, sectionData in sectionInfo.items():
                entropy = float(sectionData["Entropy"])
                if entropy > 7: # threshold value
                    peInfo["Report"]["High entropy detected"] = {
                        "|": "Entropy is a measure of randomness in data. Sections with high entropy may indicate overlay, encoded, or encrypted data"
                    }
                        
        # check for overlay data in virtual and raw sizes
        if pe.OPTIONAL_HEADER.SizeOfImage < os.path.getsize(pePath):
            peInfo["Report"]["Contains overlay data"] = {
                "|": "The file has data beyond the declared SizeOfImage, which may indicate it was signed or embeded / encoded with data"
            }
        
        # check if DEP is enabled
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x100:
            peInfo["Report"]["DEP is Enabled"] = {
                "|": "Data Execution Prevention is a security feature that marks memory pages as executable or non-executable, and prevents execution of code in non-executable pages, making buffer overflow vulnerabilities more difficult to exploit"
            }

        # check if ASLR is enabled
        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
            peInfo["Report"]["ASLR is Enabled"] = {
                "|": "Address Space Layout Randomization is a security feature that randomizes the layout of the address space of a module, which makes buffer overflow vulnerabilities more difficult to exploit"                 
            }
            
        # check for truncation in sizes
        if os.path.getsize(pePath) < pe.OPTIONAL_HEADER.SizeOfImage:
            peInfo["Report"]["Truncated sample"] = {
                "|": "The file size is less than the size of the image in the Optional Header - this sample may be truncated"
            }

        # check if sample has a security directory
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            peInfo["Report"]["Contains a security directoryd"] = {
            "|": "The file has an embedded security directory which may explain overlay data"
        }
        
        # check for TLS section
        for section in pe.sections:
            if section.Name.decode("utf-8").strip('\x00').lower() == ".tls":
                peInfo["Report"]["Contains a TLS section"] = {
                    "|": "Thread-local storage is normally used to manage data in multithreaded apps. It can also allow execution of code outside expected entry points in the PE"
                }

        # check for unusual entry point
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < pe.OPTIONAL_HEADER.ImageBase:
            peInfo["Report"]["Contains unusual entry point"] = {
                "|": "The specified starting address for execution is lower than the Image Base address indicating a packed or obfuscated file. Typical PE behavior executes with a virtual address greater than or equal to the Image Base address"
            }

        detectedPacker = detect_packer(pePath)
        if detectedPacker:
            peInfo["Report"]["Detected Packer"] = [detectedPacker]
            
        peInfo["Section Info"] = sectionInfo  
        
        peInfo["Report"]["Suspicious APIs Detected"] = []

        # extract import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            moduleName = entry.dll.decode("utf-8")
            moduleInfo = {"Module": moduleName, "Functions": []}
            susModuleInfo = {"In module": moduleName, "APIs": []}

            for imp in entry.imports:
                funcName = imp.name.decode("utf-8") if imp.name else "Ordinal {}".format(imp.ordinal)
                funcInfo = {"Name": funcName, "Ordinal": imp.ordinal, "Import Address": hex(imgBase + imp.address)}
                moduleInfo["Functions"].append(funcInfo)
                susAPI = malAPI_Check(funcName)

                if susAPI is not None:
                    susModuleInfo["APIs"].append([susAPI])
                    
            if susModuleInfo["APIs"]:
                peInfo["Report"]["Suspicious APIs Detected"].append([susModuleInfo])

            peInfo["Import Table"].append(moduleInfo)

        binStrings = extract_strings(pePath)
        peInfo["Report"]["Interesting Strings"] = get_interesting_strings(binStrings)
        


        # extract exported functions
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                funcName = exp.name.decode("utf-8")
                funcAddress = hex(imgBase + exp.address)
                exportedFuncInfo = {"Function": funcName, "Export Address": hex(imgBase + exp.address)}
                

                # try to find the import address for the exported function
                impAddress = None
                ordinal = None
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode("utf-8") == exp.name.decode("utf-8"):
                            impAddress = hex(imgBase + imp.address)
                            ordinal = imp.ordinal
                            break
                
                if impAddress:
                    exportedFuncInfo["Import Address"] = impAddress
                if ordinal is not None:
                    exportedFuncInfo["Ordinal"] = ordinal                
                
                peInfo["Exported Functions"].append(exportedFuncInfo)
                
        if not peInfo["Exported Functions"]:
            del peInfo["Exported Functions"]                
        
        peInfo["Memory Graphs"] = {"Raw Size": {}, "Virtual Size": {}}
        maxRawSize = max(int(sectionData["Raw Size"], 16) for sectionData in sectionInfo.values())
        maxVirtSize = max(int(sectionData["Virtual Size"], 16) for sectionData in sectionInfo.values())

        for sectionName, sectionData in sectionInfo.items():
            rawSize = int(sectionData["Raw Size"], 16)
            virtSize = int(sectionData["Virtual Size"], 16)
            
            peInfo["Memory Graphs"]["Raw Size"][sectionName] = draw_bar_graph(sectionName, rawSize, maxRawSize)
            peInfo["Memory Graphs"]["Virtual Size"][sectionName] = draw_bar_graph(sectionName, virtSize, maxVirtSize)

        #  finally write to a JSON file
        with open(outFile1, "w") as f2:
            json.dump(peInfo, f2, indent=4)
        if not silent:    
            print(f"Analysis result saved to {outFile1}\n")
    except pefile.PEFormatError as e:
        # print("Error parsing PE file:", str(e))
        pass
            
                
                   
#--------------------- end of PE analysis ---------------------#
                    #- Extraction Methods -#         
                
            
        
def merge_json(file1, file2, outFile1):
    with open(file1, 'r') as f1:
        data1 = json.load(f1)
    with open(file2, 'r') as f2:
        data2 = json.load(f2)
    mergeData = {**data1, **data2}

    with open(outFile1, 'w') as output:
        json.dump(mergeData, output, indent=4)
  
def extract_winrar(inPath, outPath, password=None):
    try:
        rarPath = "C:\\Program Files\\WinRAR\\WinRAR.exe"  # >>> RESET TO SERVER PATH <<< #
        extractCmd = [rarPath, "x", "-ibck", "-y"] 
        
        # use the password if one is provided
        if password:
            extractCmd.append(f"-p{password}")
        
        extractCmd.extend([inPath, outPath])
        
        try:
            process = subprocess.Popen(extractCmd)
            
            # kill the subprocess if it takes logner than 24seconds
            process.wait(timeout=24)
        except subprocess.TimeoutExpired:
            process.terminate()
            time.sleep(1)
            
            if process.poll() is None:
                process.kill()
                process.wait()
            # print("Extraction process terminated - trying with 7-zip.\n")
            pass
        except subprocess.CalledProcessError as e:
            # print(f"Error: {e} - trying with 7-zip.\n")
            pass
    except: 
        extract_winrar(inPath, outPath, password)        

def extract_7z(inPath, outPath, password=None):
    sevenZip_path = "C:\\Program Files\\7-Zip\\7z.exe"  # >>> RESET TO SERVER PATH <<< #
    extractCmd = [sevenZip_path, "x", "-y"] 
    
    # use the password if one is provided
    if password:
        extractCmd.append(f"-p{password}")
    
    extractCmd.extend([inPath, outPath])
    
    try:
        process = subprocess.Popen(extractCmd)
        
        # kill the subprocess if it takes logner than 24seconds
        process.wait(timeout=24)
    except subprocess.TimeoutExpired:
        process.terminate()
        time.sleep(1)
        
        if process.poll() is None:
            process.kill()
            process.wait()
        # print("Extraction process terminated - timeout.")
    except subprocess.CalledProcessError as e:
        # print(f"Error: {e}")        
        pass

def extract_msi_table_data(msi_file):
    tables = ['UIText', 'Registry', 'RegLocator', 'InstallExecuteSequence', 'File', 'FeatureComponents', 'Feature', 'Environment', 'Directory', 'CustomAction']

    db = msilib.OpenDatabase(msi_file, msilib.MSIDBOPEN_READONLY)
    comData = {}

    # grab COM struct table data
    for table in tables:
        try:
            tableView = db.OpenView(f"SELECT * FROM {table}")
            tableView.Execute(None)
            tableData = {}
            while True:
                tableRow = tableView.Fetch()
                if not tableRow:
                    break
                rowData = [tableRow.GetString(i) for i in range(1, tableRow.GetFieldCount() + 1)]
                tableData[rowData[0]] = rowData[1:]
            comData[table] = {"data": tableData}
        except msilib.MSIError:
            # print(f"Table not found in the MSI file: {table}")
            pass

    rename_keys(comData, 'InstallExecuteSequence', 'Install Sequence')
    rename_keys(comData, 'UIText', 'UI Text')
    rename_keys(comData, 'RegLocator', 'Reg Locator')
    rename_keys(comData, 'FeatureComponents', 'Feature Comps')
    rename_keys(comData, 'CustomAction', 'Custom Action')

    return comData
             
             
            
        
def analysis_main(sample, silent=False):
    password=None
    wholePath = os.path.abspath(sample)
    file = os.path.basename(sample)
    rootFolder = os.path.splitext(os.path.basename(sample))[0]
    currentTime = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    
    if not os.path.exists('extracted'):
        os.mkdir('extracted') 
        pass    
    
    i = 1
    subPath = os.path.join(f'extracted\\{rootFolder}-{currentTime}')
    while os.path.exists(subPath):
        currentTime = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        subPath = os.path.join('extracted\\{rootFolder}-{currentTime}')

    if not os.path.exists(subPath):
        os.mkdir(subPath) 
        pass
        


    # no extraction needed
    if valid_sample(file, sample): 
        sampleFiles = [file]
        samplePaths = [wholePath]
        analysisData = []
        fileData = []        
    
    # no extraction needed - and sample is not a valid pe32 format file - plain read
    elif not file.lower().endswith(('.7z', '.zip', '.msi', '.iso', '.gz')):
        if not silent:
            print("Sample is not a valid PE or Archive")
        time.sleep(1)
        fileRead = open(wholePath, 'r').read()
        outFile1 = os.path.join(subPath, f'{file}_plain-text.json')
        sampleFiles = [fileRead]
        if not silent:
            print("Saving plain-text", end='', flush=True)
        with open(outFile1, 'w') as f:
            json.dump(sampleFiles, f, indent=4)
        if not silent:
            time.sleep(0.3)
            for _ in range(3):
                print(".", end='', flush=True)
                time.sleep(0.3)              
        return
    
    # extraction needed    
    else:
            extractedFolder = f'[EXTRACTED]-{rootFolder}'

            i = 1
            while os.path.exists(os.path.join(subPath, extractedFolder)):
                extractedFolder = f'[EXTRACTED]-{rootFolder}-{i}'
                i += 1
            extractedFolder = os.path.join(subPath, extractedFolder)
            os.makedirs(extractedFolder, exist_ok=True)

            if sample.lower().endswith('.msi'):
                if not silent:
                    print(f"Extracted - MSI files are in '{extractedFolder}'")

                msiData = extract_msi_table_data(sample)
                msiOutFile = os.path.join(subPath, f'{os.path.splitext(os.path.basename(sample))[0]}.msi_com_analysis.json')
                with open(msiOutFile, 'w') as json_file:
                    json.dump(msiData, json_file, indent=2)  
                if not silent:
                    print(f"Analysis results of MSI data saved to '{msiOutFile}'")
                extract_winrar(sample, extractedFolder, password)            
                rootPath = extractedFolder
            else:    
                extract_winrar(sample, extractedFolder, password)
                rootPath = extractedFolder
                if not silent:
                    print(f"Extracted - files are in '{extractedFolder}'")
        
            # loops until there are no more archive file types to extract
            def extract_and_analyze(root):
                for item in os.listdir(root):
                    itemPath = os.path.join(root, item)
                    if os.path.isdir(itemPath):
                        extract_and_analyze(itemPath)
                    elif itemPath.lower().endswith(('.7z', '.zip', '.msi', '.iso', '.gz')):
                        if itemPath.lower().endswith('.msi'):
                            extractedFolder = os.path.splitext(os.path.basename(itemPath))[0]
                            extractedFolder = os.path.join(root, f'[EXTRACTED]-{extractedFolder}{os.path.splitext(item)[1]}')
                            os.makedirs(extractedFolder, exist_ok=True)
                            if not silent:
                                print(f"Extracted - MSI files are in '{extractedFolder}'")

                            msiData = extract_msi_table_data(itemPath)
                            msiOutFile = os.path.join(subPath, f'{os.path.splitext(os.path.basename(itemPath))[0]}.msi_com_analysis.json')
                            with open(msiOutFile, 'w') as json_file:
                                json.dump(msiData, json_file, indent=2) 
                            if not silent:
                                print(f"Analysis results of MSI data saved to '{msiOutFile}'")
                            extract_winrar(itemPath, extractedFolder, password)
                        else:
                            extractedFolder = os.path.splitext(os.path.basename(itemPath))[0]
                            extractedFolder = os.path.join(root, f'[EXTRACTED]-{extractedFolder}{os.path.splitext(item)[1]}')
                            os.makedirs(extractedFolder, exist_ok=True)
                            extract_winrar(itemPath, extractedFolder, password)
                            if not silent:
                                print(f"Extracted - files are in '{extractedFolder}'")

            extract_and_analyze(extractedFolder)
            
            
            

            sampleFiles = []
            samplePaths = []
            analysisData = []
            fileData = []

            for root, dirs, files in os.walk(rootPath):
                for file in files:
                    filePath = os.path.join(root, file).replace('\\', '/')
                    if valid_sample(file, filePath):
                        sampleFiles.append(file)
                        samplePaths.append(filePath)
                        
    
    if not silent:
        print("\nAnalyzing:\n")           
    for i in range(len(sampleFiles)):
        if not silent:
            print(f"File: {sampleFiles[i]}\nPath: {samplePaths[i]}")
        outFile1 = os.path.join(subPath, f'{sampleFiles[i]}_extraction.json')
        outFile2 = os.path.join(subPath, f'{sampleFiles[i]}_analysis.json')
        analyze_executable(samplePaths[i], outFile1)
        extract_pe_info(samplePaths[i], outFile2, silent)
        analysisData.append(outFile1)
        analysisData.append(outFile2)         
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Maguna File Analysis')
    parser.add_argument('filePath', help='Accepts path to a file or archive for analysis')
    parser.add_argument('-s', '--silent', action='store_true', help='Quiet mode...')
    args = parser.parse_args()
    filePath = args.filePath
    silent = args.silent
    
    analysis_main(filePath, silent)
