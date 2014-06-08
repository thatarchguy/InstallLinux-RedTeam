#include <Windows.h>
#include <Strsafe.h>
#include "zlib.h"
#define IMAGE_PATH "image.gz"
#define REQUIRED_PARTITION_SIZE 1024
#define WRITESTRING(fh,buf,result) if(WriteFile(fh,buf,lstrlenA(buf),result,NULL) == FALSE){printf("Could not write %s!\n",buf); ExitProcess(1);}
//Reads from a file handle until a '>' is encountered
void getPrompt(HANDLE fh){
	CHAR buf[1024];
	DWORD read = 0;
	while(ReadFile(fh, buf, sizeof(buf), &read, NULL))
		for(DWORD i = 0; i < read; i++)
			if(buf[i] == '>')
				return;
}
//Reads into buffer until it hits a prompt, return # read bytes
DWORD readPrompt(HANDLE fh, PCHAR buf, DWORD buflen){
	DWORD origbuflen = buflen;
	DWORD read = 0;
	while(buflen > 0 && ReadFile(fh, buf, buflen, &read, NULL)){
		buflen -= read;
		for(DWORD i = 0; i < read; i++){
			if(buf[i] == '>')
				return origbuflen - buflen;
		}
		buf += read;
	}
	GetLastError();
	return origbuflen;
}
//Reads until >, and returns whether string showed up in one of the reads
bool checkPrompt(HANDLE fh, PCHAR string){
	CHAR buf[1024];
	DWORD read = 0;
	DWORD len = lstrlenA(string);
	while(ReadFile(fh, buf, sizeof(buf), &read, NULL)){
		for(DWORD i = 0; i < read; i++){
			if(i < read - len && memcmp(string, &(buf[i]), len) == 0)
				return true;
			else if(buf[i] == '>')
				return false;
		}
	}
	return false;
}
int main(){
	printf("Initial disk check...\n");
	HANDLE rawdriveh = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DWORD numBytes = 512;
	BYTE originalMBR[512];
	//if it is not successful or it's not an MBR,
	if(rawdriveh == INVALID_HANDLE_VALUE || ReadFile(rawdriveh, originalMBR, 512, &numBytes, 0) == FALSE
			|| numBytes != 512 || originalMBR[510] != 0x55 || originalMBR[511] != 0xAA){
		printf("Cannot open disk or device not MBR-based\n");
		return 1;
	}
	//Now we could totally save originalMBR, but might not want to.

	//Also, we're going to open the Linux image file right away here because 
	//if it's not there, we don't want to partition
	gzFile linuxImage = gzopen(IMAGE_PATH, "rb");
	if(linuxImage == NULL){
		printf("Cannot open linux image file!\n");
		return 1;
	}

	printf("Opening disk manager\n");

	SECURITY_ATTRIBUTES saAttr; 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL;
	HANDLE stdoutRd, stdoutWr, stdinRd, stdinWr, stderrRd, stderrWr;

	// Create pipes for diskpart stdin/out/err
	if ( ! CreatePipe(&stdoutRd, &stdoutWr, &saAttr, 0)
			|| ! SetHandleInformation(stdoutRd, HANDLE_FLAG_INHERIT, 0)
			|| ! CreatePipe(&stdinRd, &stdinWr, &saAttr, 0)
			|| ! SetHandleInformation(stdinWr, HANDLE_FLAG_INHERIT, 0) 
			|| ! CreatePipe(&stderrRd, &stderrWr, &saAttr, 0) 
			|| ! SetHandleInformation(stderrRd, HANDLE_FLAG_INHERIT, 0) )
		ExitProcess(1);

	// Start proc
	PROCESS_INFORMATION piProcInfo; 
	STARTUPINFOA siStartInfo;
	ZeroMemory( (PBYTE) &piProcInfo, sizeof(piProcInfo) );
	ZeroMemory( (PBYTE) &siStartInfo, sizeof(siStartInfo) );
	siStartInfo.cb = sizeof(STARTUPINFO); 
	siStartInfo.hStdError = stderrWr;
	siStartInfo.hStdOutput = stdoutWr;
	siStartInfo.hStdInput = stdinRd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	if(!CreateProcessA("C:\\Windows\\System32\\diskpart.exe", "diskpart.exe", NULL,
			NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo)){
		printf("Could not start process.\n");
		return 1;
	}

	//Partition!
	CHAR textbuf[4096];
	DWORD size;
	printf("Getting system volume info...\n");
	//Get system drive
	CHAR systemDrive[10];
	systemDrive[0] = 'C'; // by default
	GetEnvironmentVariableA("SystemDrive", systemDrive, sizeof(systemDrive));
	systemDrive[1] = 0;

	//Get initial prompt
	getPrompt(stdoutRd);

	//Select volume
	StringCbPrintfA(textbuf, sizeof(textbuf), "select volume %s\n", systemDrive);
	WRITESTRING(stdinWr, textbuf, &size)
	if(checkPrompt(stdoutRd, "not valid")){
		printf("Cannot select system volume %s\n", systemDrive);
		return TerminateProcess(piProcInfo.hProcess, 0);
	}

	//Get disk info
	WRITESTRING(stdinWr, "detail disk\n", &size);
	size = readPrompt(stdoutRd, textbuf, sizeof(textbuf));
	textbuf[sizeof(textbuf)-1] = 0;
	DWORD partitionCount = 0;
	for(PCHAR ppr = strstr(textbuf,"Partition"); ppr != NULL; ppr = strstr(ppr + 1,"Partition"))
		partitionCount++;
	printf("Found %d partitions\n", partitionCount);
	if(partitionCount >= 4){
		printf("Too many partitions active; only 4 may be specified in the MBR!\n");
		return TerminateProcess(piProcInfo.hProcess, 0);
	}

	printf("Trying to add partition without affecting existing partitions...\n");
	StringCbPrintfA(textbuf, sizeof(textbuf), "create partition primary size=%d\n",
		REQUIRED_PARTITION_SIZE);
	WRITESTRING(stdinWr, textbuf, &size)
	if(!checkPrompt(stdoutRd, "succeeded")){
		printf("Cannot add new, attempting to shrink existing system volume...\n");

		//ask how much it can shrink
		WRITESTRING(stdinWr, "shrink querymax\n", &size)
		//looks like "The maximum number of reclaimable bytes is:  106 GB (109316 MB)"
		//or maybe "The maximum number of reclaimable bytes is:  "
		size = readPrompt(stdoutRd, textbuf, sizeof(textbuf));
		PCHAR numStr = textbuf;
		bool gigabytes = true;
		for(DWORD numstart = 0; numstart < size; numstart++){
			if(numStr == textbuf && textbuf[numstart] >= '0' && textbuf[numstart] <= '9')
				numStr = textbuf + numstart;
			else if(textbuf[numstart] == '('){
				gigabytes = false;
				numStr = textbuf + numstart + 1;
			}else if(textbuf[numstart] == ' ')
				textbuf[numstart] = 0;
		}
		DWORD numfree = atoi(numStr);
		if(gigabytes)
			numfree = numfree * 1024; // Microsoft uses 2^10 not 10^3

		StringCbPrintfA(textbuf, sizeof(textbuf), "Found %d mb free in system.\n", numfree);
		printf("%s",textbuf);
		if(numfree < REQUIRED_PARTITION_SIZE){
			printf("Need %d mb!\n", REQUIRED_PARTITION_SIZE);
			return TerminateProcess(piProcInfo.hProcess, 0);
		}

		//Make partition smaller
		StringCbPrintfA(textbuf, sizeof(textbuf), "shrink desired=%d minimum=%d\n", 
			REQUIRED_PARTITION_SIZE, REQUIRED_PARTITION_SIZE);
		WRITESTRING(stdinWr, textbuf, &size);
		size = readPrompt(stdoutRd, textbuf, sizeof(textbuf));
		textbuf[sizeof(textbuf)-1] = 0;
		if(strstr(textbuf,"error") != NULL){
			printf("Error shrinking system drive!\n");
			return TerminateProcess(piProcInfo.hProcess, 0);
		}else if(strstr(textbuf, "success") == NULL){
			printf("Something strange happened shrinking system drive!\n");
			return TerminateProcess(piProcInfo.hProcess, 0);
		}
		printf("Successfuly shrunk system volume, creating new partition...\n");

		StringCbPrintfA(textbuf, sizeof(textbuf), "create partition primary size=%d\n",
			REQUIRED_PARTITION_SIZE);
		WRITESTRING(stdinWr, textbuf, &size)
		if(checkPrompt(stdoutRd, "No usable free")){
			printf("Still cannot add partition! Manually investigate.\n");
			return TerminateProcess(piProcInfo.hProcess, 0);
		}
	}
	printf("Successfully added partition.\nConfiguring partition ");

	//Get partition number
	WRITESTRING(stdinWr, "detail partition\n", &size);
	size = readPrompt(stdoutRd, textbuf, sizeof(textbuf));
	textbuf[sizeof(textbuf) - 1] = 0;
	PCHAR ppr = strstr(textbuf, "Partition ");
	if(ppr == NULL){
		printf("Cannot get partition info!\n");
		return TerminateProcess(piProcInfo.hProcess, 0);
	}
	DWORD partNum = ppr[10] - '0'; //get number
	printf("%d\n", partNum);

	//Set ID
	WRITESTRING(stdinWr, "set id=83\n", &size)
	if(!checkPrompt(stdoutRd, "success")){
		printf("Cannot set partition ID! Manually investigate.\n");
		return TerminateProcess(piProcInfo.hProcess, 0);
	}
	
	//We're done with diskpart
	WRITESTRING(stdinWr, "exit\n", &size);
	if(WaitForSingleObject(piProcInfo.hProcess, 5000) != WAIT_OBJECT_0){
		printf("Warning - diskpart not exiting... killing zombie and continuing anyway\n");
		// just in case it's not dead already, kill the zombie
		TerminateProcess(piProcInfo.hProcess, 0); 
	}

	//Now back to the MBR
	printf("Reading MBR\n");
	BYTE newWinMBR[512];
	//Let's get the current MBR
	if(SetFilePointer(rawdriveh, 0, 0, 0) != 0 || 
			ReadFile(rawdriveh, newWinMBR, 512, &numBytes, 0) == FALSE || numBytes != 512){
		printf("Cannot read new MBR\n");
		return 1;
	}
	//Let's write the linux image from its file to the raw partition
	printf("Writing new partition data...\n");
	CHAR partpath[MAX_PATH];
	StringCbPrintfA(partpath, sizeof(partpath), "\\\\?\\GLOBALROOT\\Device\\Harddisk0\\Partition%d", partNum);
	HANDLE rawparth = CreateFileA(partpath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(rawparth == INVALID_HANDLE_VALUE){
		printf("Cannot open raw partition for writing!\n");
		return 1;
	}
	int read = 0;
	DWORD wrote;
	BYTE data[16384];
	//loop reading in all the data
	while((read = gzread(linuxImage, data, sizeof(data))) != 0 && read != -1){
		//The file with 512 consecutive X's needs to be replaced with the MBR
		int numXs = 0;
		for(int i = 0; i < read; i++){
			if(data[i] == 'X'){
				numXs++;
				if(numXs == 512){
					memcpy(&(data[i - 512 + 1]), newWinMBR, 512);
					printf("Saving old MBR to use in virtual guest\n");
				}
			}else{
				numXs = 0;
			}
		}
		//Now write out the data we got
		if(!WriteFile(rawparth, data, read, &wrote, NULL))
			printf("Error writing to new partition! %d\n", GetLastError());
	}
	CloseHandle(rawparth);
	gzclose(linuxImage);

	//OK, now let's fix our MBR
	printf("Generating new MBR with our bootloader...\n");
	//Copy in new bootloader code, courtesy of syslinux
	PBYTE mbrcode = (PBYTE)"\x33\xc0\xfa\x8e\xd8\x8e\xd0\xbc\x00\x7c\x89\xe6\x06\x57"
		"\x8e\xc0\xfb\xfc\xbf\x00\x06\xb9\x00\x01\xf3\xa5\xea\x1f\x06\x00\x00"
		"\x52\x52\xb4\x41\xbb\xaa\x55\x31\xc9\x30\xf6\xf9\xcd\x13\x72\x13\x81"
		"\xfb\x55\xaa\x75\x0d\xd1\xe9\x73\x09\x66\xc7\x06\x8d\x06\xb4\x42\xeb"
		"\x15\x5a\xb4\x08\xcd\x13\x83\xe1\x3f\x51\x0f\xb6\xc6\x40\xf7\xe1\x52"
		"\x50\x66\x31\xc0\x66\x99\xe8\x66\x00\xe8\x21\x01\x4d\x69\x73\x73\x69"
		"\x6e\x67\x20\x6f\x70\x65\x72\x61\x74\x69\x6e\x67\x20\x73\x79\x73\x74"
		"\x65\x6d\x2e\x0d\x0a\x66\x60\x66\x31\xd2\xbb\x00\x7c\x66\x52\x66\x50"
		"\x06\x53\x6a\x01\x6a\x10\x89\xe6\x66\xf7\x36\xf4\x7b\xc0\xe4\x06\x88"
		"\xe1\x88\xc5\x92\xf6\x36\xf8\x7b\x88\xc6\x08\xe1\x41\xb8\x01\x02\x8a"
		"\x16\xfa\x7b\xcd\x13\x8d\x64\x10\x66\x61\xc3\xe8\xc4\xff\xbe\xbe\x7d"
		"\xbf\xbe\x07\xb9\x20\x00\xf3\xa5\xc3\x66\x60\x89\xe5\xbb\xbe\x07\xb9"
		"\x04\x00\x31\xc0\x53\x51\xf6\x07\x80\x74\x03\x40\x89\xde\x83\xc3\x10"
		"\xe2\xf3\x48\x74\x5b\x79\x39\x59\x5b\x8a\x47\x04\x3c\x0f\x74\x06\x24"
		"\x7f\x3c\x05\x75\x22\x66\x8b\x47\x08\x66\x8b\x56\x14\x66\x01\xd0\x66"
		"\x21\xd2\x75\x03\x66\x89\xc2\xe8\xac\xff\x72\x03\xe8\xb6\xff\x66\x8b"
		"\x46\x1c\xe8\xa0\xff\x83\xc3\x10\xe2\xcc\x66\x61\xc3\xe8\x62\x00\x4d"
		"\x75\x6c\x74\x69\x70\x6c\x65\x20\x61\x63\x74\x69\x76\x65\x20\x70\x61"
		"\x72\x74\x69\x74\x69\x6f\x6e\x73\x2e\x0d\x0a\x66\x8b\x44\x08\x66\x03"
		"\x46\x1c\x66\x89\x44\x08\xe8\x30\xff\x72\x13\x81\x3e\xfe\x7d\x55\xaa"
		"\x0f\x85\x06\xff\xbc\xfa\x7b\x5a\x5f\x07\xfa\xff\xe4\xe8\x1e\x00\x4f"
		"\x70\x65\x72\x61\x74\x69\x6e\x67\x20\x73\x79\x73\x74\x65\x6d\x20\x6c"
		"\x6f\x61\x64\x20\x65\x72\x72\x6f\x72\x2e\x0d\x0a\x5e\xac\xb4\x0e\x8a"
		"\x3e\x62\x04\xb3\x07\xcd\x10\x3c\x0a\x75\xf1\xcd\x18\xf4\xeb\xfd\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00";
	memcpy(newWinMBR, mbrcode, 440); //because it's 440 bytes. deal therewith.
	//Set us as active partition
	bool needToSetBootable = true;
	PBYTE partitionTable = &(newWinMBR[0x01BE]); //Get pointer to first partition record
	//unfortunately, the number Windows displays as the partition number has little to
	//do with the layout on disk. Let's look for a type 83 partion, and error if we find
	//more than one (would have to be a weird system)
	for(DWORD i = 0; i < 4; i++){
		if(needToSetBootable && partitionTable[4] == 0x83){
			partitionTable[0] = 0x80;
			needToSetBootable = false;
		}else if(partitionTable[4] == 0x83){
			printf("Error - multiple candidate partitions - dunno which to use.\n");
			return 1;
		}else{
			partitionTable[0] = 0; //un-bootablize the other partitions
		}
		partitionTable += 16; //each partition record is 16 bytes
	}
	if(needToSetBootable){ //still need to set, we must have missed it
		printf("Error - couldn't set bootable flag on partition %d!\n",partNum);
	}

	//Write the new MBR!
	numBytes = 0;
	if(SetFilePointer(rawdriveh, 0, 0, 0) != 0 || 
			WriteFile(rawdriveh, newWinMBR, 512, &numBytes, 0) == FALSE || numBytes != 512){
		printf("Error writing new MBR!\n");
		return 1;
	}
	CloseHandle(rawdriveh);
	printf("Wrote new MBR - should be all ready to reboot!\n");
	return 0;
}