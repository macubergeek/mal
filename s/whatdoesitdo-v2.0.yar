rule Process_Creation_detected
{ 
strings:
   $a = "CreateProcess"
   $b = "ShellExec"
   $c = "ShellExecute"
   $d = "WinExec"
   $e = "exec"
   $f = "execve"
   $g = "system"
condition:
   any of them
}
rule DLL_or_Thread_Injection_detected
{ 
strings:
   $a = "CreateToothelp32Snapshot"
   $b = "Process32First"
   $c = "Process32Next"
   $d = "Module32First"
   $e = "Module32Next"
   $f = "OpenProcess"
   $g = "VirtualAlloc"
   $h = "WriteProcessMemory"
   $i = "CreateRemoteThread"
   $j = "WaltForSingleObject"
   $k = "CreateEvent"
condition:
   any of them
}
rule Registry_modification_detection
{ 
strings:
	$a = "RegCreateKey"
	$b = "RegOpenKey"
	$c = "RegCloseKey"
	$d = "software"
	$e = "system"
	$f = "CurrentVersion"
	$g = ".reg"
	$h = "regedit"
	$i = "reg.exe"
condition:
   any of them
}
rule Shell_Injection_detected
{
strings:
	$a = "shell open"
	$b = "exefile"
	$c = "batfile"
	$d ="comfile"
	$e = "ddeexec"
	$f = "Classes Folder"
	$g = "Classes CSLID"
	$h = "InProcServer32"
condition:
   any of them
}
rule Browser_injection_detected
{
strings:
	$a = "Internet Explorer"
	$b = "Extensions"
	$c = "Explorer Bars"
	$d = "Script"
	$e = "Exec"
	$f = "Browser Helper Objects"
	$g = "InprocServer32"
	$h = "URLSearchHook"
	$i = "Implemented Categories"
	$j = "InitPropertyBag Url"
	$k = "iexplore.exe"
condition:
   any of them
}
rule Network_Communications_detected
{
strings:
	$a = "InternetOpenFile"
	$b = "InternetReadFile"
	$c = "InternetOpen"
	$d = "IUnRteLrnetConnect"
	$e = "UrlDownloadialle"
	$f = "socket"
	$g = "WSASocket"
	$h = "connect"
	$i = "WSAConnect"
	$j = "http:////"
	$k = "www"
	$l = ".com" 
	$m = ".org"
	$n = ".net"
	$o = "HTTP//1.0"
	$p = "Content-Type"
	$q = "User-Agent"
	$r = "GET"
	$s = "PRIVMSG"
	$t = "PUT"
	$u = "JOIN"
	$v = "RCPT"
	$w = "DATA"
	$x = "MAIL"
	$y = "HELO"
	$z = "EHLO"
	$a1 = "USER"
	$a2 = "POST"
condition:
   any of them
}
rule IRC_communications_detected
{
	strings:
	$a = "JOIN" nocase
	$b = "NICK" nocase
	$c = "IRC"
condition:
	any of them
}
rule SQL_injection_detected
{
	strings:
	$a = "SELECT" nocase
	$b = "JOIN" nocase
	$c = "LIMIT" nocase
	$d = "WHERE" nocase
	$e = "DROP" nocase
condition:
	any of them
}
rule Rootkit_with_Hooks_detected
{
strings:
	$a = "LoadLibrary"
	$b = "GetProcAddress"
	$c = "GetWindowThreadProcessID"
	$d = "SetWindowsHookEx"
condition:
	$a and $b and $c and $d
}
rule Rootkit_with_CreateRemote_Thread_detected
{
strings:
	$a = "OpenProcess"
	$b = "VirtualAllocEx"
	$c = "WriteProcessMemory"
	$d = "GetModuleHandle"
	$e = "GetProcAddress"
	$f = "CreateRemoteThread"
	$g = "LoadLibrary"
condition:
	$a and $b and $c and $d and $e and $f and $g
}
rule API_Hooking_detected
{
strings:
	$a = "GetProcAddress"
	$b = "VirtualProtect"
	$c = "ReadProcessMemory"
	$d = "VirtualProtect"
condition:
	$a and $b and $c and $d
}
rule Keylogger_detected
{
strings:
	$a = "GetAsyncKeyState"
	$b = "SetWindowsHookExA"
	$c = "GetKeyState"
	$d = "KBDLLHOOKSTRUCT"
condition:
	any of them
}
rule Sniffer_detected
{
strings:
	$a = "WSASocket"
	$b = "socket"
	$c = "bind"
	$d = "WSAIoctl" 
	$e = "ioctlsocket"

condition:
	any of them
}
rule Dropper_file_detected
{
strings:
	$a = "URLDownloadToFile"
	$b = "ShellExecute"
	$c = "WinExec"
	$d = "CreateFile"
condition:
	$a and $b or $c and $d
}
rule HTTP_connections_Command_and_Control_detected
{
strings:
	$a = "InternetOpen"
	$b = "InternetConnect"
	$c = "HttpOpenRequest"
	$d = "HttpSendRequest"
	$e = "InternetReadFile"
condition:
	$a or $b and $c and $d and $e
}
rule vmdetect_VMdetection_detected
{
	strings: 
	$vm0 = "VIRTUAL" nocase 
	$vm1 = "VMWARE VIRTUAL IDE HARD DRIVE" nocase 
	$vm2 = "QEMU HARDDISK" nocase 
	$vm3 = "VBOX HARDDRIVE" nocase 
	$vm4 = "The Wireshark Network Analyzer"
	$vm5 = "C:\\sample.exe" 
	$vm6 = "C:\\windows\\system32\\sample_1.exe"
	$vm7 = "Process Monitor - Sysinternals: www.sysinternals.com"
	$vm8 = "File Monitor - Sysinternals: www.sysinternals.com"
	$vm9 = "Registry Monitor - Sysinternals: www.sysinternals.com"
condition: 
	any of them 
}
rule autorun_item_creation_detected
{
	meta:
	description = "Indicates attempt to spread through autorun"
	strings:
	$a = "[autorun]"
	$b = "open="
	
condition:
	all of them
}
rule Capture_Webcam_images_functionality_detected
{
	strings:
	$a = "capCreateCaptureWindowA"
condition:
	any of them
}
rule Write_a_file
{
	strings:
	$a = "WriteFile"
condition:
	all of them
}
rule FTP_download_remote_file
{
	strings:
	$a = "FtpOpenFileA"
condition:
	all of them
}
rule FTP_APIs
{
	strings:
	$a = "FtpFindFirstFileA"
    $b = "FtpGetFileA"
    $c = "FtpPutFileA"
    $d = "FtpDeleteFileA"
    $e = "FtpRenameFileA"
    $f = "FtpOpenFileA"
    $g = "FtpCreateDirectoryA"
    $h = "FtpRemoveDirectoryA"
    $i = "FtpSetCurrentDirectoryA"
    $j = "FtpGetCurrentDirectoryA"
    $k = "FtpCommandA"
    $l = "FtpGetFileSize"
    $m = "FtpGetSystemNameA"
    $n = "FtpFindNextFileA"
    $o = "FtpReadFile"
    $p = "FtpWriteFile"
    $q = "pFtpGetUrlString"
condition:
	any of them
}
rule Database_communication_detected
{
	strings:
	$a = "SQLAllocHandle"
	$b = "SQLColAttributeW"
	$c = "SQLDisconnect"
	$d = "SQLDriverConnectW"
	$e = "SQLExecDirectW"
	$f = "SQLFetch"
	$g = "SQLFreeHandle"
	$h = "SQLGetData"
	$i = "SQLGetDiagRecW"
	$j = "SQLMoreResults"
	$k = "SQLNumResultCols"
	$l = "SQLSetEnvAttr"
condition:
		any of them
}
rule Anti-Reversing_detected
{
	strings:
	$a = "NtQueryObject"
	$b = "RtlGetNTGlobalFlags"
	$c = "NtQuerySystemInformation"
	$d = "NtQueryInformationProcess"
	$e = "GetTickCount"
	$f = "KiUserExceptionDispatcher"
	$g = "GetVersion"
	$h = "KiRaiseUserExceptionDispatcher"
	$i = "IsDebuggerPresent"
	$j = "NtGlobalFlag"
	$k = "HeapFlag"
condition:
		any of them
}