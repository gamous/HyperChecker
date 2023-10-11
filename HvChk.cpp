#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")

#define PKUSER_SHARED_DATA 0x7FFE0000
#define GetBuildNumber()  (*(UINT32 *)(PKUSER_SHARED_DATA + 0x0260))
#define GetMajorVersion() (*(UINT32 *)(PKUSER_SHARED_DATA + 0x026C))
#define GetMinorVersion() (*(UINT32 *)(PKUSER_SHARED_DATA + 0x0270))
#define GetSafeBootMode() (*(UCHAR *) (PKUSER_SHARED_DATA + 0x02ec))
#define GetVirtualFlags() (*(UCHAR *) (PKUSER_SHARED_DATA + 0x02ed))

// NtQuery Define 
typedef struct _HV_DETAILS{
    ULONG Data[4];
} HV_DETAILS, * PHV_DETAILS;
typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION{
    HV_DETAILS HvVendorAndMaxFunction;
    HV_DETAILS HypervisorInterface;
    HV_DETAILS HypervisorVersion;
    HV_DETAILS HvFeatures;
    HV_DETAILS HwFeatures;
    HV_DETAILS EnlightenmentInfo;
    HV_DETAILS ImplementationLimits;
} SYSTEM_HYPERVISOR_DETAIL_INFORMATION, * PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef enum _SYSTEM_INFORMATION_CLASS{
    SystemHypervisorDetailInformation = 159 // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
} SYSTEM_INFORMATION_CLASS;
EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
    IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID               SystemInformation,
    IN  ULONG                SystemInformationLength,
    OUT PULONG              ReturnLength OPTIONAL);
EXTERN_C NTSTATUS NTAPI SyscallTermMyProc(
    IN HANDLE               ProcessHandle OPTIONAL,
    IN NTSTATUS             ExitStatus);
// NtQuery Define END


#define _T_CHAR 'o'
#define _F_CHAR 'x'
#define TF(x) x?_T_CHAR:_F_CHAR

EXTERN_C BOOL _asm_check_ind();
EXTERN_C BOOL _asm_check_lbr();
EXTERN_C void _asm_set_tf();
EXTERN_C void __fastcall _asm_fyl2xp1();

typedef struct _cpuid_buffer_t{
    INT32 eax;
    INT32 ebx;
    INT32 ecx;
    INT32 edx;
}cpuid_buffer_t;
#define STATUS_HV_DETECTED    true
#define STATUS_HV_NOT_PRESENT false

bool CpuidCheck(){
    // Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX 
    cpuid_buffer_t regs;
    __cpuid((INT32*)&regs, 1);
    return (regs.ecx & 0x80000000) != 0;
}

// resouces https://kb.vmware.com/s/article/1009458
char* GetHvName(){
    cpuid_buffer_t regs;
    // we know hypervisor is present we can query the vendor id.
    __cpuid((INT32*)&regs, 0x40000000);
    // construct string for our vendor name
    char* presentVendor = new char[13];
    memcpy(presentVendor,&regs.ebx,12);
    presentVendor[12] = '\0';
    return presentVendor;
}
char* GetCpuName(){
    char* presentVendor = new char[48];
    cpuid_buffer_t regs;
    __cpuid((INT32*)&regs, 0x80000002);
    memcpy(presentVendor,&regs,16);
    __cpuid((INT32*)&regs, 0x80000003);
    memcpy(presentVendor+16,&regs,16);
    __cpuid((INT32*)&regs, 0x80000004);
    memcpy(presentVendor+32,&regs,32);
    presentVendor[47] = '\0';
    return presentVendor;
}
bool CheckKnownVendor(){
    const char* presentVendor = GetHvName();
    constexpr auto size      = 13;
    // check against known vendor names
    const char* vendors[]{
        "KVMKVMKVM\0\0\0", // KVM 
        "Microsoft Hv",    // Microsoft Hyper-V or Windows Virtual PC */
        "VMwareVMware",    // VMware 
        "XenVMMXenVMM",    // Xen 
        "prl hyperv  ",    // Parallels
        "VBoxVBoxVBox"     // VirtualBox 
    };
    for (const auto& vendor : vendors){
        if (!memcmp(vendor, presentVendor, size)) return true;
    }
    return false;
}


//bool LBRStackChecks(){
//// Save current LBR top of stack
//auto last_branch_taken_pre = __read_lbr_tos();
//
//// Force VM-exit with CPUID
//__cpuid(0, &regs);
//
//// Save post VM-exit LBR top of stack
//auto last_branch_taken_post = __read_lbr_tos();
//
//// Compare last branch taken
//if(last_branch_taken_pre != last_branch_taken_post)
//    return TRUE;
//}

bool CheckIndv(){
    __try {
        return _asm_check_ind();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool CheckLBRBadVirt(){
    __try {
        return _asm_check_lbr();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#synthetic-msrs
bool KiSyntheticMsrCheck(){ 
    #define HV_SYNTHETIC_MSR_RANGE_START 0x40000002
    __try{
        __readmsr(HV_SYNTHETIC_MSR_RANGE_START);
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
        return false;
    }
    return true;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#cpuid-leaf-comparisons
bool CheckInvalidLeaf() {
    constexpr unsigned int invalid_leaf = 0x04201337;
    constexpr unsigned int valid_leaf   = 0x40000000;

    _cpuid_buffer_t InvalidLeafResponse = {};
    _cpuid_buffer_t ValidLeafResponse   = {};

    __cpuid((INT32*)(&InvalidLeafResponse), invalid_leaf);
    __cpuid((INT32*)(&ValidLeafResponse), valid_leaf);

    if ((InvalidLeafResponse.eax != ValidLeafResponse.eax) ||
        (InvalidLeafResponse.ebx != ValidLeafResponse.ebx) ||
        (InvalidLeafResponse.ecx != ValidLeafResponse.ecx) ||
        (InvalidLeafResponse.edx != ValidLeafResponse.edx))
        return true;
    return false;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#cpuid-leaf-comparisons
bool CheckHighestLowFunctionLeaf(){
    cpuid_buffer_t regs;
    __cpuid((INT32*)&regs, 0x40000000);

    cpuid_buffer_t reserved_regs;
    __cpuid((INT32*)&reserved_regs, 0);
    __cpuid((INT32*)&reserved_regs, reserved_regs.eax);

    if (reserved_regs.eax != regs.eax || 
        reserved_regs.ebx != regs.ebx || 
        reserved_regs.ecx != regs.ecx || 
        reserved_regs.edx != regs.edx)
        return true;
    return false;
}

bool CheckTimeRdtscCpuid(){
    DWORD tsc1 = 0;
    DWORD tsc2 = 0;
    DWORD avg = 0;
    INT cpuInfo[4] = {};
    for (INT i = 0; i < 10; i++){
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        tsc2 = __rdtsc();
        avg += (tsc2 - tsc1);
    }
    avg = avg / 10;
    return (avg < 500 && avg > 25) ? false : true;
}

bool CheckTimeRdtscpCpuid() {
    unsigned int  blabla = 0;
    unsigned int tscp1 = 0;
    unsigned int tscp2 = 0;
    DWORD avg = 0;
    INT cpuid[4] = {};
    for (INT j = 0; j < 10; j++){
        tscp1 = __rdtscp(&blabla);
        __cpuid(cpuid, 0);
        tscp2 = __rdtscp(&blabla);
        avg += tscp2 - tscp1;
        if (avg < 500 && avg > 25)
            return false;  
        else
            avg = 0;
    }
    return true;
}
bool CheckTimeRdtscHeap() {
    DWORD tsc1;
    DWORD tsc2;
    DWORD tsc3;
    for (DWORD i = 0; i < 10; i++){
        tsc1 = __rdtsc();
        GetProcessHeap();
        tsc2 = __rdtsc();
        CloseHandle(0);
        tsc3 = __rdtsc();
        if ((tsc3 - tsc2) / (tsc2 - tsc1) >= 10)
            return false;  
    }
    return true;
}

// resources [check #Improvement Part https://secret.club/2020/01/12/battleye-hypervisor-detection.html] 
bool be_take_time(){
    // If the CPUID instruction execution time is longer than the arithmetic
    // instruction it’s a reliable indication that the system is virtualized
    // because under no circumstances should the arithmetic instruction take
    // longer than the CPUID execution to grab vendor, or version information.
    // This detection will also catch those using TSC offsetting/scaling.

    constexpr auto measure_time = 20;

    long long __cpuid_time = 0;
    long long __fyl2xp1_time = 0;

    LARGE_INTEGER frequency = {};
    LARGE_INTEGER start = {};
    LARGE_INTEGER end = {};

    QueryPerformanceFrequency(&frequency);

    // count the average time it takes to execute a CPUID instruction
    for (size_t i = 0; i < measure_time; ++i){
        QueryPerformanceCounter(&start);
        _cpuid_buffer_t cpuid_data;
        __cpuid(reinterpret_cast<int*>(&cpuid_data), 1);
        QueryPerformanceCounter(&end);

        auto delta = end.QuadPart - start.QuadPart;

        delta *= 1000000000;
        delta /= frequency.QuadPart;

        __cpuid_time += delta;
    }

    // count the average time it takes to execute a FYL2XP1 instruction
    for (size_t i = 0; i < measure_time; ++i){
        QueryPerformanceCounter(&start);
        #ifdef _WIN64
        _asm_fyl2xp1();
        #else
        _asm FYL2XP1
        #endif
        QueryPerformanceCounter(&end);

        auto delta = end.QuadPart - start.QuadPart;

        delta *= 1000000000;
        delta /= frequency.QuadPart;

        __fyl2xp1_time += delta;
    }

    return __fyl2xp1_time <= __cpuid_time;
}

// resources [check https://secret.club/2020/01/12/battleye-hypervisor-detection.html] #Improvement Part
bool CheckTimeFyl2xp1Cpuid(){
    constexpr auto measure_times = 20;
    auto positives = 0;
    auto negatives = 0;

    // run the internal VM check multiple times to get an average result
    for (auto i = measure_times; i != 0; --i)
        be_take_time() ? ++positives : ++negatives;

    // if there are more positive results than negative results, the
    // process is likely running inside a VM
    const bool decision = (positives >= negatives);

    return decision;
}

// resources https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/hypervisor_detail.htm
bool CheckSysHvInfo(){
    SYSTEM_HYPERVISOR_DETAIL_INFORMATION systInformat{0};
    ULONG retLenth = NULL;
    NtQuerySystemInformation(SystemHypervisorDetailInformation,&systInformat,sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION), &retLenth);
    return  systInformat.ImplementationLimits.Data[0] != 0     //SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HV_IMPLEMENTATION_LIMITS->MaxVirtualProcessorCount
        &&  systInformat.HypervisorInterface.Data[0] != 0      //SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HV_HYPERVISOR_INTERFACE_INFO->Interface
        &&  systInformat.EnlightenmentInfo.Data[0] != 0        //SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HV_X64_ENLIGHTENMENT_INFORMATION
        &&  systInformat.HvVendorAndMaxFunction.Data[0] != 0   //SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HvVendorAndMaxFunction->Interface || SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HvVendorAndMaxFunction->Reserved1
        &&  systInformat.HvVendorAndMaxFunction.Data[1] != 0;  //SYSTEM_HYPERVISOR_DETAIL_INFORMATION->HV_IMPLEMENTATION_LIMITS->MaxVirtualProcessorCount
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#debug-exception-db-w-tf
int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep, bool& bDetected, int& singleStepCount){
    if (code != EXCEPTION_SINGLE_STEP){
        bDetected = true;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    singleStepCount++;
    if ((size_t)ep->ExceptionRecord->ExceptionAddress != (size_t)_asm_set_tf + 11){
        bDetected = true;
        return EXCEPTION_EXECUTE_HANDLER;
    }
    bool bIsRaisedBySingleStep = ep->ContextRecord->Dr6 & (1 << 14);
    bool bIsRaisedByDr0 = ep->ContextRecord->Dr6 & 1;
    if (!bIsRaisedBySingleStep || !bIsRaisedByDr0){
        bDetected = true;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
bool SehCpuid(){
    bool bDetected = 0;
    int singleStepCount = 0;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = (size_t)_asm_set_tf + 11;
    ctx.Dr7 = 1;
    SetThreadContext(GetCurrentThread(), &ctx);
    __try{
        ((void(*)())&_asm_set_tf)();
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation(), bDetected, singleStepCount)){
        if (singleStepCount != 1){
            bDetected = 1;
        }
    }
    return bDetected;
}

int main(){
    printf("---------------\n");
    printf("-SYSTEM--------\n");
    printf("System:      %d %d.%d\n",GetBuildNumber(),GetMajorVersion(),GetMinorVersion());
    printf("SafeBoot:    %c\n", TF(GetSafeBootMode()));
    printf("HVM support: %c\n",TF(GetVirtualFlags()));
    printf("HvInfo:      %c\n",TF(CheckSysHvInfo()));
    printf("---------------\n");
    printf("-FLAG----------\n");
    printf("Cpuid:       %c\n",TF(CpuidCheck()));
    printf("CpuidLeaf1:  %c\n",TF(CheckInvalidLeaf()));
    printf("CpuidLeaf2:  %c\n",TF(CheckHighestLowFunctionLeaf()));
    //printf("Msr:         %c\n",TF(KiSyntheticMsrCheck()));
    //printf("Indv:        %c\n",TF(CheckIndv()));
    //printf("LBRBadVirt:  %c\n",TF(CheckLBRBadVirt()));
    printf("---------------\n");
    printf("-TIME----------\n");
    printf("Rdtsc:       %c\n",TF(CheckTimeRdtscCpuid()));
    printf("Rdtscp:      %c\n",TF(CheckTimeRdtscpCpuid()));
    printf("Fyl2xp1:     %c\n",TF(CheckTimeFyl2xp1Cpuid()));
    //printf("Rdtsc(Heap): %c\n",TF(CheckTimeRdtscHeap()));
    //printf("---------------\n");
    //printf("-VMX-Trap------\n");
    //printf("BE:          %c\n",TF(SehCpuid()));
    printf("-VENDOR--------\n");
    printf("Known:       %c\n",TF(CheckKnownVendor()));
    printf("HyperVisor:  %s\n",GetHvName());
    printf("Hardware:    %s\n",GetCpuName());
    printf("---------------\n");
    printf("-Result-------\n");
    if( CpuidCheck()
        ||CheckInvalidLeaf()
        ||CheckHighestLowFunctionLeaf()
        ||CheckTimeFyl2xp1Cpuid()
        ||CheckTimeRdtscCpuid()
        ||CheckTimeRdtscpCpuid()){
        if(CheckKnownVendor())
            printf("Detected Known Hypervisor:%s\n",GetHvName());
        else
            printf("Detected Unknown Hypervisor!!!\n");
        
    }
    else{
        printf("No Hypervisor\n");
    }

    return 0;
}