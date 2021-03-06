///////////////////////////////////////////////////////////////////////////////
//
//    (C) Copyright 2019 Xilinx, Inc.
//    (C) Copyright 2019 OSR Open Systems Resources, Inc.
//    All Rights Reserved
//
//    ABSTRACT:
//
//       IOCTL interface definitions for the Xilinx XOCL driver
//
///////////////////////////////////////////////////////////////////////////////
#pragma once

//
// Device interface GUID for the BME280 device
//
#include <initguid.h>
#include <stdint.h>

// {45A6FFCA-EF63-4933-9983-F63DEC5816EB}
DEFINE_GUID(GUID_DEVINTERFACE_XOCL_USER,
    0x45a6ffca, 0xef63, 0x4933, 0x99, 0x83, 0xf6, 0x3d, 0xec, 0x58, 0x16, 0xeb);

#define FILE_DEVICE_XOCL_USER   ((ULONG)0x8879)   // "XO"

// 
// Constant string for the symbolic link associated with the device
// 
#define XOCL_USER_BASE_DEVICE_NAME               L"XOCL_USER-"

//
// Device name space names
//
#define XOCL_USER_DEVICE_BUFFER_OBJECT_NAMESPACE L"\\Buffer"
#define XOCL_USER_DEVICE_DEVICE_NAMESPACE        L"\\Device"

//
// IOCTL Codes and structures supported by XoclUser
// 

typedef enum _XOCL_BUFFER_SYNC_DIRECTION {

    XOCL_BUFFER_DIRECTION_TO_DEVICE = 0,
    XOCL_BUFFER_DIRECTION_FROM_DEVICE

} XOCL_BUFFER_SYNC_DIRECTION, *PXOCL_BUFFER_SYNC_DIRECTION;

typedef enum _XOCL_BUFFER_TYPE {

    XOCL_BUFFER_TYPE_NONE = 0,
    XOCL_BUFFER_TYPE_NORMAL = 0x3323,
    XOCL_BUFFER_TYPE_USERPTR,
    XOCL_BUFFER_TYPE_IMPORT,
    XOCL_BUFFER_TYPE_CMA,
    XOCL_BUFFER_TYPE_P2P,
    XOCL_BUFFER_TYPE_EXECBUF

} XOCL_BUFFER_TYPE, *PXOCL_BUFFER_TYPE;

#define XOCL_MAX_DDR_BANKS    4

//
// Creating and using Buffer Objects
//
// Instantiating Buffer Objects is a two step process:
//
// 1) An empty Buffer Object is created on the device, using CreateFile
//      specifying XOCL device's buffer namespace (e.g. "XOCL_USER-0\Buffer").
//      The File Handle returned from the successful CreateFile operation is
//      the handle to the newly created empty Buffer Object.
//
// 2) An IOCTL is sent, via the File Handle of the empty Buffer Object
//      created in step 1 above, to complete the creation of the Buffer Object.
//      The IOCTL will be either IOCTL_XOCL_CREATE_BO or IOCTL_XOCL_USERPTR_BO.
//
// After a Buffer Object has been created as described above, Sync, Map (if
// appropriate), PREAD, PWRITE, INFO, and EXECBUF (if appropriate) operations
// can be performed using the Buffer Object, by sending the associated IOCTL
// on the File Handle of the Buffer Object.  For EXECBUF, dependent File Handles
// may optionally be specified in the provided dependency buffer.
//
// To destroy the buffer object simply call CloseHandle on the HANDLE returned
// by the CreateFile call
//

//
// IOCTL_XOCL_CREATE_BO
//
// InBuffer = XOCL_CREATE_BO_ARGS
// OutBuffer = (not used)
//
#define IOCTL_XOCL_CREATE_BO        CTL_CODE(FILE_DEVICE_XOCL_USER, 2070, METHOD_BUFFERED, FILE_READ_DATA)
//
typedef struct _XOCL_CREATE_BO_ARGS {
    ULONGLONG               Size;           // IN: Size in bytes of Buffer
    ULONG                   BankNumber;     // IN: Zero-based DDR bank number to use
    XOCL_BUFFER_TYPE        BufferType;     // IN: Which type of Buffer Object is being created
                                            //     Must be "NORMAL" or "EXECBUF"
} XOCL_CREATE_BO_ARGS, *PXOCL_CREATE_BO_ARGS;

//
// IOCTL_XOCL_USERPTR_BO
//
// InBuffer  = XOCL_USERPTR_BO_ARGS
// OutBuffer = (not used)
// 
#define IOCTL_XOCL_USERPTR_BO       CTL_CODE(FILE_DEVICE_XOCL_USER, 2071, METHOD_BUFFERED, FILE_READ_DATA)
//
typedef struct _XOCL_USERPTR_BO_ARGS {
    PVOID                   Address;        // IN: User VA of buffer for driver to use
    ULONGLONG               Size;           // IN: Size in bytes of buffer
    ULONG                   BankNumber;     // IN: Zero-based DDR bank number to use
    XOCL_BUFFER_TYPE        BufferType;     // IN: Which type of Buffer Object is being created
                                            //     Must be "USERPTR"
} XOCL_USERPTR_BO_ARGS, *PXOCL_USERPTR_BO_ARGS;

//
// IOCTL_XOCL_MAP_BO
//
// InBuffer =  (not used)
// OutBuffer = XOCL_MAP_BO_RESULT
//
#define IOCTL_XOCL_MAP_BO           CTL_CODE(FILE_DEVICE_XOCL_USER, 2072, METHOD_BUFFERED, FILE_READ_DATA)
//
typedef struct _XOCL_MAP_BO_RESULT {
    PVOID       MappedUserVirtualAddress;         // OUT: User VA of mapped buffer
} XOCL_MAP_BO_RESULT, *PXOCL_MAP_BO_RESULT;

//
// IOCTL_XOCL_SYNC_BO
//
// InBuffer =  XOCL_SYNC_BO_ARGS
// OutBuffer =  (not used)
//
#define IOCTL_XOCL_SYNC_BO          CTL_CODE(FILE_DEVICE_XOCL_USER, 2073, METHOD_BUFFERED, FILE_READ_DATA)
//
typedef struct _XOCL_SYNC_BO_ARGS {
    ULONGLONG   Size;           // IN: Bytes to read or write
    ULONGLONG   Offset;         // IN: DDR offset, in bytes, for sync operation
    XOCL_BUFFER_SYNC_DIRECTION Direction;  // IN: Sync direction (FROM device or TO device)
} XOCL_SYNC_BO_ARGS, *PXOCL_SYNC_BO_ARGS;

//
// IOCTL_XOCL_INFO_BO
//
// InBuffer =  (not used)
// OutBuffer = XOCL_INFO_BO_RESULT
//
#define IOCTL_XOCL_INFO_BO          CTL_CODE(FILE_DEVICE_XOCL_USER, 2075, METHOD_BUFFERED, FILE_READ_DATA)
//
typedef struct _XOCL_INFO_BO_RESULT {
    ULONGLONG           Size;           // OUT: Size in bytes of the buffer
    ULONGLONG           Paddr;          // OUT: Physical address of associated DDR
    XOCL_BUFFER_TYPE    BufferType;     // OUT: Buffer Type
} XOCL_INFO_BO_RESULT, *PXOCL_INFO_BO_RESULT;

//
// IOCTL_XOCL_READ_AXLF
//
// InBuffer =  User data buffer pointer and size (containing AXLF File)
// OutBuffer = (not used)
//
#define IOCTL_XOCL_READ_AXLF        CTL_CODE(FILE_DEVICE_XOCL_USER, 2076, METHOD_BUFFERED, FILE_READ_DATA)


//
// IOCTL_XOCL_MAP_BAR
//
// InBuffer =  (not used)
// OutBuffer = XOCL_MAP_BAR_RESULT
//
#define IOCTL_XOCL_MAP_BAR      CTL_CODE(FILE_DEVICE_XOCL_USER, 2077, METHOD_BUFFERED, FILE_READ_DATA)

#define XOCL_MAP_BAR_TYPE_USER     0
#define XOCL_MAP_BAR_TYPE_CONFIG   1
#define XOCL_MAP_BAR_TYPE_BYPASS   2
#define XOCL_MAP_BAR_TYPE_MAX      3

typedef struct _XOCL_MAP_BAR_ARGS {
    ULONG BarType; // IN: XOCL_MAP_BAR_TYPE_XXX
} XOCL_MAP_BAR_ARGS, *PXOCL_MAP_BAR_ARGS;

typedef struct _XOCL_MAP_BAR_RESULT {
    PVOID       Bar;           // OUT: User VA of mapped buffer
    ULONG       BarLength;     // OUT: Length of mapped buffer
} XOCL_MAP_BAR_RESULT, *PXOCL_MAP_BAR_RESULT;

//
// IOCTL_XOCL_STAT
//
// InBuffer =  XOCL_STAT_CLASS_ARGS
// OutBuffer = Varies
//
#define IOCTL_XOCL_STAT      CTL_CODE(FILE_DEVICE_XOCL_USER, 2078, METHOD_BUFFERED, FILE_READ_DATA)

typedef enum _XOCL_STAT_CLASS {

    XoclStatDevice = 0xCC,
    XoclStatMemTopology,
    XoclStatMemRaw,
    XoclStatIpLayout,
    XoclStatKds,
    XoclStatKdsCU,

} XOCL_STAT_CLASS, *PXOCL_STAT_CLASS;

typedef struct _XOCL_STAT_CLASS_ARGS {

    XOCL_STAT_CLASS StatClass;

} XOCL_STAT_CLASS_ARGS, *PXOCL_STAT_CLASS_ARGS;

// 
// XoclStatDevice
// 
typedef struct _XOCL_DEVICE_INFORMATION {
    ULONG  DeviceNumber;
    USHORT Vendor;
    USHORT Device;
    USHORT SubsystemVendor;
    USHORT SubsystemDevice;
    ULONG  DmaEngineVersion;
    ULONG  DriverVersion;
    ULONG  PciSlot;

} XOCL_DEVICE_INFORMATION, *PXOCL_DEVICE_INFORMATION;
#if 0
// 
// XoclStatMemTopology
// 
typedef GUID xuid_t;
#else
typedef unsigned char xuid_t[16];
#endif

typedef struct _XU_MEM_TOPO_DATA {

    UCHAR m_type; //enum corresponding to mem_type.
    UCHAR m_used; //if 0 this bank is not present
    union {
        ULONGLONG m_size; //if mem_type DDR, then size in KB;
        ULONGLONG route_id; //if streaming then "route_id"
    };
    union {
        ULONGLONG m_base_address;//if DDR then the base address;
        ULONGLONG flow_id; //if streaming then "flow id"
    };
    UCHAR m_tag[16]; //DDR: BANK0,1,2,3, has to be null terminated; if streaming then stream0, 1 etc

} XU_MEM_TOPO_DATA, *PXU_MEM_TOPO_DATA;

typedef struct _XOCL_MEM_TOPOLOGY_INFORMATION {

    ULONG        MemTopoCount;

    XU_MEM_TOPO_DATA MemTopo[XOCL_MAX_DDR_BANKS];

} XOCL_MEM_TOPOLOGY_INFORMATION, *PXOCL_MEM_TOPOLOGY_INFORMATION;

// 
// XoclStatMemRaw
// 
typedef struct _XOCL_MEM_RAW {
    ULONGLONG               MemoryUsage;
    ULONGLONG               BOCount;
} XOCL_MEM_RAW, *PXOCL_MEM_RAW;

typedef struct _XOCL_MEM_RAW_INFORMATION {

    ULONG        MemRawCount;
    XOCL_MEM_RAW MemRaw[XOCL_MAX_DDR_BANKS];

} XOCL_MEM_RAW_INFORMATION, *PXOCL_MEM_RAW_INFORMATION;
#if 0
//
// XoclStatIpInfo
//
enum IP_TYPE {
    IP_MB = 0,
    IP_KERNEL, //kernel instance
    IP_DNASC,
    IP_DDR4_CONTROLLER
};
#endif
typedef struct _XU_IP_DATA {
    uint32_t m_type; //map to IP_TYPE enum
    union {
        uint32_t properties; //32 bits to indicate ip specific property. eg if m_type == IP_KERNEL then bit 0 is for interrupt.
        struct {     // Used by IP_MEM_* types
            uint16_t m_index;
            uint8_t m_pc_index;
            uint8_t unused;
        } indices;
    };
    uint64_t m_base_address;
    uint8_t m_name[64]; //eg Kernel name corresponding to KERNEL instance, can embed CU name in future.
} XU_IP_DATA, *PXU_IP_DATA;

typedef struct _XU_IP_LAYOUT {
    int32_t m_count;
    XU_IP_DATA m_ip_data[1]; //All the XU_IP_DATA needs to be sorted by m_base_address.
} XU_IP_LAYOUT, *PXU_IP_LAYOUT;

// 
// XoclStatKds
// 
typedef struct _XOCL_KDS_INFORMATION {
    xuid_t    XclBinUuid;
    ULONG     OutstandingExecs;
    ULONGLONG TotalExecs;
    ULONG     ClientCount;
    ULONG     CDMACount;
    ULONG     CuCount;
} XOCL_KDS_INFORMATION, *PXOCL_KDS_INFORMATION;

// 
// XoclStatKdsCU
// 
typedef struct _XOCL_KDS_CU {

    ULONG BaseAddress;
    ULONG Usage;

} XOCL_KDS_CU, *PXOCL_KDS_CU;

typedef struct _XOCL_KDS_CU_INFORMATION {

    ULONG       CuCount;
    XOCL_KDS_CU CuInfo[1];

} XOCL_KDS_CU_INFORMATION, *PXOCL_KDS_CU_INFORMATION;

//
// IOCTL_XOCL_PREAD_BO
//
// Inbuffer =  XOCL_PREAD_BO
// OutBuffer = User data buffer pointer and size (Direct I/O)
//             The OutBuffer length indicates requested size of the read.
//
#define IOCTL_XOCL_PREAD_BO         CTL_CODE(FILE_DEVICE_XOCL_USER, 2100, METHOD_OUT_DIRECT, FILE_READ_DATA)

typedef struct _XOCL_PREAD_BO_ARGS {
    ULONGLONG   Offset;     // IN: BO offset to read from 
} XOCL_PREAD_BO_ARGS, *PXOCL_PREAD_BO_ARGS;


//
// IOCTL_XOCL_PWRITE_BO
//
// Inbuffer =  XOCL_PWRITE_BO
// OutBuffer = User data buffer pointer and size (Direct I/O)
//             The OutBuffer length indicates requested size of the write.
//
#define IOCTL_XOCL_PWRITE_BO        CTL_CODE(FILE_DEVICE_XOCL_USER, 2101, METHOD_IN_DIRECT, FILE_READ_DATA)

typedef struct _XOCL_PWRITE_BO_ARGS {
    ULONGLONG   Offset;     // IN: BI offset to write to 
} XOCL_PWRITE_BO_ARGS, *PXOCL_PWRITE_BO_ARGS;


//
// IOCTL_XOCL_CTX
//
// Inbuffer = XOCL_CTX_ARGS
// OutBuffer = (not used)
//
#define IOCTL_XOCL_CTX              CTL_CODE(FILE_DEVICE_XOCL_USER, 2102, METHOD_BUFFERED, FILE_READ_DATA)

typedef enum _XOCL_CTX_OPERATION {

    XOCL_CTX_OP_ALLOC_CTX,
    XOCL_CTX_OP_FREE_CTX

}XOCL_CTX_OPERATION, *PXOCL_CTX_OPERATION;

#define XOCL_CTX_FLAG_SHARED    0x0
#define XOCL_CTX_FLAG_EXCLUSIVE 0x1

typedef struct _XOCL_CTX_ARGS {
    XOCL_CTX_OPERATION Operation;   // IN: Alloc or free context
    xuid_t             XclBinUuid;  // IN: XCLBIN to acquire a context on
    ULONG              CuIndex;     // IN: Compute unit for the request
    ULONG              Flags;       // IN: XOCL_CTX_FLAG_XXX values
} XOCL_CTX_ARGS, *PXOCL_CTX_ARGS;

//
// IOCTL_XOCL_EXECBUF
//
// Inbuffer = XOCL_EXECBUF_ARGS
// OutBuffer = (not used)
//
#define IOCTL_XOCL_EXECBUF          CTL_CODE(FILE_DEVICE_XOCL_USER, 2103, METHOD_BUFFERED, FILE_READ_DATA)

typedef struct _XOCL_EXECBUF_ARGS {
    HANDLE      ExecBO;
    HANDLE      Deps[8];    // IN: Dependent Buffer Object handles
} XOCL_EXECBUF_ARGS, *PXOCL_EXECBUF_ARGS;

//
// IOCTL_XOCL_EXECPOLL
//
// Inbuffer = XOCL_EXECPOLL_ARGS
// OutBuffer = (not used)
//
#define IOCTL_XOCL_EXECPOLL          CTL_CODE(FILE_DEVICE_XOCL_USER, 2104, METHOD_BUFFERED, FILE_READ_DATA)

typedef struct _XOCL_EXECPOLL_ARGS {
    ULONG DelayInMS;        // IN: Poll delay in microseconds
} XOCL_EXECPOLL_ARGS, *PXOCL_EXECPOLL_ARGS;

