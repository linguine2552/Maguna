# Analysis Report Example
```yaml
{
    "Report": {
        "DEP is Enabled": {
            "|": "Data Execution Prevention is a security feature that marks memory pages as executable or non-executable, and prevents execution of code in non-executable pages, making buffer overflow vulnerabilities more difficult to exploit"
        },
        "ASLR is Enabled": {
            "|": "Address Space Layout Randomization is a security feature that randomizes the layout of the address space of a module, which makes buffer overflow vulnerabilities more difficult to exploit"
        },
        "Truncated sample": {
            "|": "The file size is less than the size of the image in the Optional Header - this sample may be truncated"
        },
        "Contains a TLS section": {
            "|": "Thread-local storage is normally used to manage data in multithreaded apps. It can also allow execution of code outside expected entry points in the PE"
        },
        "Contains unusual entry point": {
            "|": "The specified starting address for execution is lower than the Image Base address indicating a packed or obfuscated file. Typical PE behavior executes with a virtual address greater than or equal to the Image Base address"
        },
        "Detected Packer": [
            "UPX"
        ],
        "Suspicious APIs Detected": [
            [
                {
                    "In module": "KERNEL32.dll",
                    "APIs": [
                        [
                            "HeapAlloc - HeapAlloc is used to allocate a block of memory from a heap.    Type:Injection"
                        ],
                        [
                            "GetProcAddress - GetProcAddress is used to get the memory address of a function in a DLL. This is often used by malware for obfuscation and evasion purposes to avoid having to call the function directly.    Type:Injection Evasion"
                        ],
                        [
                            "GetProcessHeap - GetProcessHeap is used to retrieve a handle to the default heap of the calling process.    Type:Injection"
                        ],
                        [
                            "HeapReAlloc - HeapReAlloc is used to reallocate a block of memory from a heap.    Type:Injection"
                        ],
                        [
                            "FindClose - FindClose is used to close a file search handle.    Type:Helper"
                        ],
                        [
                            "WaitForSingleObjectEx - WaitForSingleObjectEx is used to delay the execution of an object. This function is commonly used to allow time for shellcode being executed within a thread to run. It is also used for time-based evasion.    Type:Injection Evasion"
                        ],
                        [
                            "IsDebuggerPresent - IsDebuggerPresent is used to determine whether the calling process is being debugged by a user-mode debugger.    Type:Anti-Debugging"
                        ],
                        [
                            "GetSystemTimeAsFileTime - Retrieves the current system date and time. The information is in Coordinated Universal Time (UTC) format. This function is commonly used by malware for anti-debugging.    Type:Enumeration Anti-Debugging"
                        ],
                        [
                            "GetCurrentProcess - GetCurrentProcess is used to retrieve a handle for the current process.    Type:Enumeration"
                        ],
                        [
                            "TerminateProcess - TerminateProcess is used to terminate a process.    Type:Helper"
                        ],
                        [
                            "QueryPerformanceCounter - QueryPerformanceCounter is used to retrieve the frequency of the performance counter. This function is commonly used by malware for anti-debugging purposes. The malware will measure the time before and after an operation, if the time exceeds taken expected time, the malware will terminate or activate a benign function.    Type:Anti-Debugging"
                        ],
                        [
                            "GetCurrentProcessId - GetCurrentProcessId is used to retrieve the process identifier of the calling process.    Type:Enumeration"
                        ],
                        [
                            "GetCurrentThreadId - GetCurrentThreadId is used to retrieve the thread identifier of the calling thread.    Type:Enumeration"
                        ]
                    ]
                }
            ]
        ],
        "Interesting Strings": {
            "URLs": [
                [
                    "http://sv.symcb.com/sv.crl0a",
                    "",
                    "",
                    "",
                    ""
                ],
                [
                    "https://d.symcb.com/cps0%",
                    "",
                    "",
                    "",
                    ""
                ],
                [
                    "www.digicert.com110/",
                    "",
                    "",
                    "",
                    ""
                ]
            ],
            "Files": [
                "RestoreDevice.pdb",
                "KERNEL32.dll",
                "SHELL32.dll",
                "SHLWAPI.dll",
                "MSVCP140.dll",
                "WINTRUST.dll",
                "VCRUNTIME140.dll",
                "api-ms-win-crt-stdio-l1-1-0.dll",
                "api-ms-win-crt-runtime-l1-1-0.dll",
                "api-ms-win-crt-heap-l1-1-0.dll",
                "api-ms-win-crt-convert-l1-1-0.dll",
                "api-ms-win-crt-environment-l1-1-0.dll",
                "api-ms-win-crt-math-l1-1-0.dll",
                "api-ms-win-crt-locale-l1-1-0.dll",
                "sv.symcb.com",
                "d.symcb.com",
                "d.symcb.com",
                "sv.symcb.com",
                "www.digicert.com",
                "crl3.digicert.com",
                "crl4.digicert.com",
                "cacerts.digicert.com",
                "cacerts.digicert.com",
                "crl4.digicert.com",
                "crl3.digicert.com",
                "www.digicert.com",
                "www.symauth.com",
                "www.symauth.com",
                "s1.symcb.com"
            ],
            "Emails": [],
            "IPs": []
        }
    },
    "Basic Info": {
        "PE Format": "Executable",
        "Compiler Architecture": "x86 (32-bit)",
        "Compilation Time": "2021-04-07 03:00:12 ",
        "File Size": "29088 bytes / 0.03 MB",
        "MD5 Hash": "89e8747486e69c4c7bd39f0af371bfbb",
        "SHA1 Hash": "d743978d3259298282cd057822de5f008a93455b",
        "SHA256 Hash": "854f1710ad93ae43e2026e2a0f9fe53f14d1be2e8b1a0a233eda6c14707f80e5",
        "Image Base": "0x00400000",
        "Entry Point": "0x00002EED",
        "File Alignment": "0x00000200",
        "Section Alignment": "0x00001000",
        "Number Of Sections": [
            7
        ],
        "File Header Characteristics": [
            "Executable Image: indicates that the image file is valid and can be run",
            "32-bit Machine: image is based on a 32-bit word architecture"
        ],
        "DLL Characteristics": [
            "Dynamic Base: dll can move at load time",
            "NX Compatible",
            "Terminal Server Aware"
        ]
    },
    "Section Info": {
        ".text": {
            "Raw Size": "0x00002A00",
            "Virtual Size": "0x0000284E",
            "Raw Address": "0x00000400",
            "Virtual Address": "0x00001000",
            "Mapped Address": "0x00401000",
            "Characteristics": "Code Section, Executable Section, Readable Section",
            "Entropy": 6.21849739999
        },
        ".rdata": {
            "Raw Size": "0x00001A00",
            "Virtual Size": "0x000018F6",
            "Raw Address": "0x00002E00",
            "Virtual Address": "0x00004000",
            "Mapped Address": "0x00404000",
            "Characteristics": "Initialized Data Section, Readable Section",
            "Entropy": 4.558496888257636
        },
        ".data": {
            "Raw Size": "0x00000200",
            "Virtual Size": "0x00000558",
            "Raw Address": "0x00004800",
            "Virtual Address": "0x00006000",
            "Mapped Address": "0x00406000",
            "Characteristics": "Initialized Data Section, Readable Section, Writable Section",
            "Entropy": 3.2698292251096492
        },
        ".tls": {
            "Raw Size": "0x00000200",
            "Virtual Size": "0x00000009",
            "Raw Address": "0x00004A00",
            "Virtual Address": "0x00007000",
            "Mapped Address": "0x00407000",
            "Characteristics": "Initialized Data Section, Readable Section, Writable Section",
            "Entropy": 0.020393135236084953
        },
        ".gfids": {
            "Raw Size": "0x00000200",
            "Virtual Size": "0x00000058",
            "Raw Address": "0x00004C00",
            "Virtual Address": "0x00008000",
            "Mapped Address": "0x00408000",
            "Characteristics": "Initialized Data Section, Readable Section",
            "Entropy": 0.4287844431336201
        },
        ".rsrc": {
            "Raw Size": "0x00000600",
            "Virtual Size": "0x000004C0",
            "Raw Address": "0x00004E00",
            "Virtual Address": "0x00009000",
            "Mapped Address": "0x00409000",
            "Characteristics": "Initialized Data Section, Readable Section",
            "Entropy": 3.5475527359718595
        },
        ".reloc": {
            "Raw Size": "0x00000400",
            "Virtual Size": "0x000003CC",
            "Raw Address": "0x00005400",
            "Virtual Address": "0x0000A000",
            "Mapped Address": "0x0040A000",
            "Characteristics": "Initialized Data Section, Readable Section, Discardable Section",
            "Entropy": 6.297207248388991
        }
    },
    "Import Table": [
        {
            "Module": "SHELL32.dll",
            "Functions": [
                {
                    "Name": "SHGetFolderPathW",
                    "Ordinal": null,
                    "Import Address": "0x8040a0"
                }
            ]
        },
        {
            "Module": "SHLWAPI.dll",
            "Functions": [
                {
                    "Name": "PathRemoveFileSpecW",
                    "Ordinal": null,
                    "Import Address": "0x8040a8"
                },
                {
                    "Name": "PathFileExistsW",
                    "Ordinal": null,
                    "Import Address": "0x8040ac"
                }
            ]
        },
        {
            "Module": "MSVCP140.dll",
            "Functions": [
                {
                    "Name": "?_Xbad_alloc@std@@YAXXZ",
                    "Ordinal": null,
                    "Import Address": "0x804090"
                },
                {
                    "Name": "?_Xlength_error@std@@YAXPBD@Z",
                    "Ordinal": null,
                    "Import Address": "0x804094"
                },
                {
                    "Name": "?_Xout_of_range@std@@YAXPBD@Z",
                    "Ordinal": null,
                    "Import Address": "0x804098"
                }
            ]
        },
        {
            "Module": "WINTRUST.dll",
            "Functions": [
                {
                    "Name": "WinVerifyTrust",
                    "Ordinal": null,
                    "Import Address": "0x8040dc"
                }
            ]
        },
        {
            "Module": "VCRUNTIME140.dll",
            "Functions": [
                {
                    "Name": "_except_handler4_common",
                    "Ordinal": null,
                    "Import Address": "0x8040b4"
                },
                {
                    "Name": "memmove",
                    "Ordinal": null,
                    "Import Address": "0x8040b8"
                },
                {
                    "Name": "memset",
                    "Ordinal": null,
                    "Import Address": "0x8040bc"
                },
                {
                    "Name": "__vcrt_InitializeCriticalSectionEx",
                    "Ordinal": null,
                    "Import Address": "0x8040c0"
                },
                {
                    "Name": "__std_exception_copy",
                    "Ordinal": null,
                    "Import Address": "0x8040c4"
                },
                {
                    "Name": "__std_exception_destroy",
                    "Ordinal": null,
                    "Import Address": "0x8040c8"
                },
                {
                    "Name": "memcpy",
                    "Ordinal": null,
                    "Import Address": "0x8040cc"
                },
                {
                    "Name": "_CxxThrowException",
                    "Ordinal": null,
                    "Import Address": "0x8040d0"
                },
                {
                    "Name": "__CxxFrameHandler3",
                    "Ordinal": null,
                    "Import Address": "0x8040d4"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-stdio-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "__stdio_common_vswprintf_s",
                    "Ordinal": null,
                    "Import Address": "0x804174"
                },
                {
                    "Name": "__p__commode",
                    "Ordinal": null,
                    "Import Address": "0x804178"
                },
                {
                    "Name": "_set_fmode",
                    "Ordinal": null,
                    "Import Address": "0x80417c"
                },
                {
                    "Name": "__stdio_common_vswprintf",
                    "Ordinal": null,
                    "Import Address": "0x804180"
                },
                {
                    "Name": "__stdio_common_vsprintf_s",
                    "Ordinal": null,
                    "Import Address": "0x804184"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-heap-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "malloc",
                    "Ordinal": null,
                    "Import Address": "0x8040f4"
                },
                {
                    "Name": "_callnewh",
                    "Ordinal": null,
                    "Import Address": "0x8040f8"
                },
                {
                    "Name": "free",
                    "Ordinal": null,
                    "Import Address": "0x8040fc"
                },
                {
                    "Name": "_set_new_mode",
                    "Ordinal": null,
                    "Import Address": "0x804100"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-convert-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "wcstol",
                    "Ordinal": null,
                    "Import Address": "0x8040e4"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-environment-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "_wgetenv_s",
                    "Ordinal": null,
                    "Import Address": "0x8040ec"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-math-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "__setusermatherr",
                    "Ordinal": null,
                    "Import Address": "0x804110"
                }
            ]
        },
        {
            "Module": "api-ms-win-crt-locale-l1-1-0.dll",
            "Functions": [
                {
                    "Name": "_configthreadlocale",
                    "Ordinal": null,
                    "Import Address": "0x804108"
                }
            ]
        }
    ],
    "Memory Graphs": {
        "Raw Size": {
            ".text": "     [||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||]",
            ".rdata": "    [|||||||||||||||||||||||||||||||||||||||||||||||||||||                                 ]",
            ".data": "     [||||                                                                                  ]",
            ".tls": "      [||||                                                                                  ]",
            ".gfids": "    [||||                                                                                  ]",
            ".rsrc": "     [||||||||||||                                                                          ]",
            ".reloc": "    [||||||||                                                                              ]"
        },
        "Virtual Size": {
            ".text": "     [||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||]",
            ".rdata": "    [|||||||||||||||||||||||||||||||||||||||||||||||||||||                                 ]",
            ".data": "     [|||||||||||                                                                           ]",
            ".tls": "      [                                                                                      ]",
            ".gfids": "    [                                                                                      ]",
            ".rsrc": "     [||||||||||                                                                            ]",
            ".reloc": "    [||||||||                                                                              ]"
        }
    }
}
