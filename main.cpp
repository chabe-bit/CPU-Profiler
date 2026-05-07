#define INITGUID
#include <windows.h>
#include <tdh.h>
#include <evntrace.h>
#include <guiddef.h>
#include <psapi.h>

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <vector>
#include <map>
#include <set>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// Suspend threads periodically
// Obtain thread context

// Stack walking 
// Given an instruction ptr, find the offset to the stackpointer to find return address to traverse the call chain

// Exclusive -> One consumer can have a handle to the kernel logger at a time. 
// A trace that had been run before a program where the program has already been reran, will
// still exist, so it's important kill that trace on launch. 
// ETWs trace kernel events such as thread swtiches, contexts ...

// Kernel tracer is asynchronous 
// Happens in the kernel (externally), not in the program loop (internal process)

#define ASSERT(x) \
	if (!(x)) { MessageBoxA(0, #x, "Assertion Failure", MB_OK); __debugbreak(); }

DEFINE_GUID( /* ce1dbfb4-137e-4da6-87b0-3f59aa102cbc */
	PerfInfoGuid,	
	0xce1dbfb4,
	0x137e,
	0x4da6,
	0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc
);

DEFINE_GUID( /* def2fe46-7bd6-4b80-bd94-f57fe20d0ce3 */
	StackWalkGuid,
	0xdef2fe46,
	0x7bd6,
	0x4b80,
	0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3
);

DEFINE_GUID( /* 3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c */
    ProcessGuid,
    0x3d6fa8d0,
    0xfe05,
    0x11d0, 
    0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c
);

DEFINE_GUID( /* 2cb15d1d-5fc1-11d2-abe1-00a0c911f518 */    
	ImageLoadGuid, 
	0x2cb15d1d,
	0x5fc1,
	0x11d2, 
	0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18
);


static WCHAR trace_log_path[] = L"C:\\Bitwise\\trace.etl";
static EVENT_TRACE_PROPERTIES *session_prop;
static TRACEHANDLE htrace_record;

static void
zzz_printf(const char *fmt, ...)
{
	char buffer[1024 * 4];
	va_list va;
	va_start(va, fmt);
	vsprintf_s(buffer, sizeof(buffer), fmt, va);
	va_end(va);
	OutputDebugStringA(buffer);
}

enum event_type {
	EVENT_STACKWALK         = 32,
	EVENT_PROFILE           = 46,
    EVENT_PROCESS_START     = 1, 
    EVENT_PROCESS_END		= 2, 
    EVENT_PROCESS_DC_START	= 3, 
    EVENT_PROCESS_DC_END    = 4, 
	EVENT_IMAGE_LOAD		= 10,
	EVENT_IMAGE_UNLOAD		= 2,
	EVENT_IMAGE_DC_START	= 3,
	EVENT_IMAGE_DC_END		= 4,  
};

struct event_sampleprofiler {
	void *instruction_ptr;
	uint32_t thread_id;
	uint32_t count;
};

struct event_stackwalk {
	uint64_t event_timestamp;
	uint32_t stack_process;
	uint32_t stack_thread;
	void *instruction_ptr[1];
};

struct event_process {
    uint32_t page_dir_base; 
    uint32_t process_id;
    uint32_t parent_id;
    uint32_t session_id;
    int32_t exit_status;
    void *reserved1;
    void *reserved2;
    void *reserved3;
    void *reserved4;
	SID user_sid;
	//char *image_filename;
};

struct event_imageload {	
	uint32_t image_base;
	uint32_t image_size;
	uint32_t process_id;
	uint32_t image_checksum;
	uint32_t time_datestamp;
	uint32_t reserved0;
	uint32_t default_base;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
	uint32_t reserved4;
	char *filename;
};

struct ImageInfo {
	
	// Loading in a DLL, the section of its code is loaded relative to each other or offsetted in a process. 
	// Every image item has a size, with that info we can determine the distance 
	// of one to another, if that makes sense.
	ImageInfo *next_image;
	size_t image_size;

	// Required - Default base is where you load by default whereas the image code above is 
	// default base + offset 
	void *default_base;
};

struct process_info {
	char *image_filename;
	char *cmd_line;
	std::vector<ImageInfo> images;
};
;

std::map<uint32_t, process_info> processes;

#if 0
const char *GetProcessName(uint32_t process_id)
{	
	auto it = processes.find(process_id);
	if (it == processes.end()) {
		HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, process_id);
        if (hproc == INVALID_HANDLE_VALUE) {
            return "";
        }
        char image_filename[MAX_PATH];
		if (GetProcessImageFileNameA(hproc, image_filename, sizeof(image_filename)) == 0) {
			return "";
		}
    }
};
#endif 

BOOL
get_event_info(EVENT_RECORD *event_record, TRACE_EVENT_INFO **event_info)
{
	DWORD status = ERROR_SUCCESS;
	DWORD event_info_size = 0;
	status = TdhGetEventInformation(event_record, 0, 0, *event_info, &event_info_size);
	if (status != ERROR_INSUFFICIENT_BUFFER) {
		return FALSE;
	}
	*event_info = (TRACE_EVENT_INFO *)malloc(event_info_size);
	ASSERT(*event_info);
	status = TdhGetEventInformation(event_record, 0, 0, *event_info, &event_info_size);
	ASSERT(status);
	return TRUE;
}

void 
print_event_properties(EVENT_RECORD *event_record)
{
	TRACE_EVENT_INFO *event_info;
	uint32_t i;
	
	if (!get_event_info(event_record, &event_info)) {
		return;
	}

	for (i = 0; i < event_info->TopLevelPropertyCount; i++) {
		LPWSTR prop_name;
		PROPERTY_DATA_DESCRIPTOR data_desc = {0};
		ULONG prop_size; 

		prop_name = (LPWSTR)((BYTE *)(event_info) + event_info->EventPropertyInfoArray[i].NameOffset);
		data_desc.PropertyName = (ULONGLONG)prop_name;
		TdhGetPropertySize(event_record, 0, 0, 1, &data_desc, &prop_size);
		zzz_printf("%S (%u)\n", prop_name, prop_size);
	}
	zzz_printf("\n");
	free(event_info);
}

#define SID_LENGTH(sid) \
    (8 + (4 * ((SID *)(sid))->SubAuthorityCount))

static void WINAPI
event_record_callback(EVENT_RECORD *event_record)
{
	UCHAR opcode = event_record->EventHeader.EventDescriptor.Opcode;
	if (IsEqualGUID(event_record->EventHeader.ProviderId, PerfInfoGuid)) {	
		switch (opcode) {
		case EVENT_PROFILE:
			event_sampleprofiler *sample = (event_sampleprofiler *)event_record->UserData;
			zzz_printf("Instruction Ptr: %llx ThreadID: %u\n", sample->instruction_ptr, sample->thread_id);
			break;
		}
	} else if (IsEqualGUID(event_record->EventHeader.ProviderId, StackWalkGuid)) {
		switch (opcode) {
			case EVENT_STACKWALK:
				uint32_t header_size = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t);
				uint32_t instruction_ptr_count = (event_record->UserDataLength - header_size) / sizeof(void *);
				uint32_t stackwalk_size = header_size + instruction_ptr_count * sizeof(void *); 
				uint32_t i;
				event_stackwalk *stackwalk = (event_stackwalk *)event_record->UserData;

				zzz_printf("TimeStamp: %llu, Process: %s, Thread: %u\n", stackwalk->event_timestamp, processes[stackwalk->stack_process], stackwalk->stack_thread);
				for (i = 0; i < instruction_ptr_count; i++) {
					void *instruction_ptr = stackwalk->instruction_ptr[i];
					zzz_printf("    0x%llx\n", instruction_ptr);
				}
				break;
		}
	} else if (IsEqualGUID(event_record->EventHeader.ProviderId, ProcessGuid)) {
        event_process *process = (event_process *)event_record->UserData;
		char *image_filename;
		switch (opcode) {
			case EVENT_PROCESS_START:
			case EVENT_PROCESS_DC_START: {
				uint32_t sid_length = GetLengthSid(&(process->user_sid)); //SID_LENGTH(&(process->user_sid));
				image_filename = (char *)&process->user_sid + sid_length;
				WCHAR *cmdline = (WCHAR *)((char *)image_filename + strlen(image_filename) + 1);
				
				processes[process->process_id].image_filename = _strdup(image_filename);

				zzz_printf("ProcessStart:\n		Image Filename: %s\n		CmdLine: %S\n", image_filename, cmdline);
				//print_event_properties(event_record);
				break;
			}
			case EVENT_PROCESS_DC_END:
			case EVENT_PROCESS_END: {
				if (process->process_id != 0) {
					auto it = processes.find(process->process_id);
					if (it != processes.end()) {
						//free(it->second);
						processes.erase(it);
					}
				}
			} break;
		}
	} else if (IsEqualGUID(event_record->EventHeader.ProviderId, ImageLoadGuid)) {
		event_imageload *image_load = (event_imageload *)event_record->UserData;	
		switch (opcode) {
			case EVENT_IMAGE_DC_START:
			case EVENT_IMAGE_LOAD:
				//zzz_printf("Image Load: %s\n", image_load->filename);
				
				break;
			case EVENT_IMAGE_UNLOAD:
			case EVENT_IMAGE_DC_END:
				break;
		}	
	}
}


void 
elevate_priviledge(void)
{
	BOOL success;
	TOKEN_PRIVILEGES token_priv;
	HANDLE token;

	success = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
	ASSERT(success);
	
	ZeroMemory(&token_priv, sizeof(token_priv));
	token_priv.PrivilegeCount = 1;
	token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &token_priv.Privileges[0].Luid);
	AdjustTokenPrivileges(token, FALSE, &token_priv, 0, (TOKEN_PRIVILEGES *)NULL, 0);
	CloseHandle(token);
}

void
profile_start_recording(void)
{
	ULONG status;
	CLASSIC_EVENT_ID event_id = { PerfInfoGuid, 46 }; // 46 -> Sampling prof

	if (trace_log_path)
		DeleteFile(trace_log_path);
	
	uint32_t buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(trace_log_path) + sizeof(KERNEL_LOGGER_NAME);
	session_prop = (EVENT_TRACE_PROPERTIES *)malloc(buffer_size);
	ASSERT(session_prop);

	ZeroMemory(session_prop, buffer_size);
	session_prop->Wnode.BufferSize = buffer_size;
	session_prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	session_prop->Wnode.ClientContext = 1;
	session_prop->Wnode.Guid = SystemTraceControlGuid;
	session_prop->EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_PROCESS;
	session_prop->LogFileMode = EVENT_TRACE_FILE_MODE_APPEND;
	session_prop->MaximumFileSize = 100; // MB 
	session_prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	session_prop->LogFileNameOffset = session_prop->LoggerNameOffset + sizeof(KERNEL_LOGGER_NAME);
	CopyMemory((char *)session_prop + session_prop->LogFileNameOffset, trace_log_path, sizeof(trace_log_path));	

	status = ControlTrace(0, KERNEL_LOGGER_NAME, session_prop, EVENT_TRACE_CONTROL_STOP);
	ASSERT(status == ERROR_SUCCESS || status == ERROR_WMI_INSTANCE_NOT_FOUND);

	status = StartTrace((PTRACEHANDLE)&htrace_record, KERNEL_LOGGER_NAME, session_prop);
	ASSERT(status == ERROR_SUCCESS);
	
	status = TraceSetInformation(htrace_record, TraceStackTracingInfo, &event_id, sizeof(event_id));
	ASSERT(status == ERROR_SUCCESS);
}

void
profile_finish_recording(void)
{
	ULONG status;
	
	status = ControlTrace(htrace_record, KERNEL_LOGGER_NAME, session_prop, EVENT_TRACE_CONTROL_STOP);
	ASSERT(status == ERROR_SUCCESS);
}

void
profile_process()
{
	// Provide file to parse
	// Callback to parse
	// Looks at the header of each file, reads the record, gives pointer then moves to the next header
	TRACEHANDLE htrace_process;
	EVENT_TRACE_LOGFILE event_trace_logfile = {0};
	
	event_trace_logfile.LogFileName = trace_log_path;
	event_trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
	event_trace_logfile.event_record_callback = event_record_callback; // Call for each event 
	
	htrace_process = OpenTrace(&event_trace_logfile);
	ProcessTrace(&htrace_process, 1, 0, 0); 
	CloseTrace(htrace_process);
}

int APIENTRY
WinMain(HINSTANCE,
		HINSTANCE,
		LPSTR,
		int)
{
	elevate_priviledge();
	profile_start_recording();
	MessageBoxA(0, "Press Enter to stop trace.", "Information", MB_OK);
	profile_finish_recording();
	profile_process();


	return 0;
}
