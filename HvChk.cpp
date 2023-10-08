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

#define _T_CHAR 'o'
#define _F_CHAR 'x'
#define TF(x) x?_T_CHAR:_F_CHAR


EXTERN_C BOOL CheckInd();
EXTERN_C UINT LBRVirt();
EXTERN_C void BEShit();
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
        CheckInd();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}
bool CheckLBRBadVirt(){
    __try {
        LBRVirt();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#synthetic-msrs
bool KiSyntheticMsrCheck(){ 
    #define HV_SYNTHETIC_MSR_RANGE_START 0x40000000
    __try{
        __readmsr(HV_SYNTHETIC_MSR_RANGE_START);
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
        return false;
    }
    return true;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#cpuid-leaf-comparisons
bool UmpIsSystemVirtualized() {
    //CPUID Leaf Comparisons
    unsigned int invalid_leaf = 0x13371337;
    unsigned int valid_leaf   = 0x40000000;
    int InvalidLeafResponse[4] = { 0,0,0,0 };
    int ValidLeafResponse[4] = { 0,0,0,0 };

    __cpuid(InvalidLeafResponse, invalid_leaf);
    __cpuid(ValidLeafResponse, valid_leaf);

    if ((InvalidLeafResponse[0] != ValidLeafResponse[0]) ||
        (InvalidLeafResponse[1] != ValidLeafResponse[1]) ||
        (InvalidLeafResponse[2] != ValidLeafResponse[2]) ||
        (InvalidLeafResponse[3] != ValidLeafResponse[3]))
        return STATUS_HV_DETECTED;
    return STATUS_HV_NOT_PRESENT;
}

// resources https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html#cpuid-leaf-comparisons
bool UmpIsSystemVirtualized2(){
    cpuid_buffer_t regs;
    __cpuid((INT32*)&regs, 0x40000000);

    cpuid_buffer_t reserved_regs;
    __cpuid((INT32*)&reserved_regs, 0);
    __cpuid((INT32*)&reserved_regs, reserved_regs.eax);

    if (reserved_regs.eax != regs.eax || 
        reserved_regs.ebx != regs.ebx || 
        reserved_regs.ecx != regs.ecx || 
        reserved_regs.edx != regs.edx)
            return STATUS_HV_DETECTED;
    return STATUS_HV_NOT_PRESENT;
}



bool RdtscCpuid(){
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

bool RdtscpCpuid() {
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
bool RdtscHeap()
{
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
        _asm_fyl2xp1();
        QueryPerformanceCounter(&end);

        auto delta = end.QuadPart - start.QuadPart;

        delta *= 1000000000;
        delta /= frequency.QuadPart;

        __fyl2xp1_time += delta;
    }

    return __fyl2xp1_time <= __cpuid_time;
}

// resources [check https://secret.club/2020/01/12/battleye-hypervisor-detection.html] #Improvement Part
bool Fyl2xp1(){
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


int main(){
    printf("System:      %d %d.%d\n",GetBuildNumber(),GetMajorVersion(),GetMinorVersion());
    printf("SafeBoot:    %c\n", TF(GetSafeBootMode()));
    printf("HVM support: %c\n",TF(GetVirtualFlags()));
    printf("---------------\n");
    printf("-FLAG----------\n");
    printf("Cpuid:       %c\n",TF(CpuidCheck()));
    printf("Msr:         %c\n",TF(KiSyntheticMsrCheck()));
    printf("Indv:        %c\n",TF(CheckIndv()));
    printf("LBRBadVirt:  %c\n",TF(CheckLBRBadVirt()));
    printf("Leaf1:       %c\n",TF(UmpIsSystemVirtualized()));
    printf("Leaf2:       %c\n",TF(UmpIsSystemVirtualized2()));
    printf("---------------\n");
    printf("-TIME----------\n");
    printf("Rdtsc:       %c\n",TF(RdtscCpuid()));
    printf("Rdtscp:      %c\n",TF(RdtscpCpuid()));
    printf("---------------\n");
    printf("-TIME??--------\n");
    printf("Rdtsc(Heap): %c\n",TF(RdtscHeap()));
    printf("Fyl2xp1:     %c\n",TF(Fyl2xp1()));

    printf("---------------\n");
    printf("-VENDOR--------\n");
    printf("-cpuid:      %s\n",GetHvName());
    

    return 0;
}