// Vita3K emulator project
// Copyright (C) 2018 Vita3K team
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#pragma once

#include <module/module.h>

enum SceAppMgrErrorCode { 
    SCE_APPMGR_ERROR_BUSY              = 0x80802000, //!< Busy
    SCE_APPMGR_ERROR_STATE             = 0x80802013, //!< Invalid state
    SCE_APPMGR_ERROR_NULL_POINTER      = 0x80802016, //!< NULL pointer
    SCE_APPMGR_ERROR_INVALID           = 0x8080201A, //!< Invalid param
    SCE_APPMGR_ERROR_TOO_LONG_ARGV     = 0x8080201D, //!< argv is too long
    SCE_APPMGR_ERROR_INVALID_SELF_PATH = 0x8080201E, //!< Invalid SELF path
    SCE_APPMGR_ERROR_BGM_PORT_BUSY     = 0x80803000  //!< BGM port was occupied and could not be secured
};

enum SceAppMgrSystemEventType {
    SCE_APPMGR_SYSTEMEVENT_ON_RESUME             = 0x10000003, //!< Application resumed
    SCE_APPMGR_SYSTEMEVENT_ON_STORE_PURCHASE     = 0x10000004, //!< Store checkout event arrived
    SCE_APPMGR_SYSTEMEVENT_ON_NP_MESSAGE_ARRIVED = 0x10000005, //!< NP message event arrived
    SCE_APPMGR_SYSTEMEVENT_ON_STORE_REDEMPTION   = 0x10000006  //!< Promotion code redeemed at PlayStationŽStore
};

typedef struct SceAppMgrSystemEvent {
    SceInt32 systemEvent;  //!< System event ID
    SceUInt8 reserved[60]; //!< Reserved data
} SceAppMgrSystemEvent;

typedef struct SceAppMgrAppState {
    SceUInt32 systemEventNum;                                       //!< Number of system events
    SceUInt32 appEventNum;                                          //!< Number of application events
    SceBool isSystemUiOverlaid;                                     //!< Truth-value of UI overlaid of system software
    SceUInt8 reserved[128 - sizeof(SceUInt32)*2 - sizeof(SceBool)]; //!< Reserved area
} SceAppMgrAppState;

typedef struct SceAppMgrLoadExecOptParam {
    int reserved[256/4]; //!< Reserved area
} SceAppMgrLoadExecOptParam;

SceInt32 _sceAppMgrGetAppState(SceAppMgrAppState *appState, SceUInt32 sizeofSceAppMgrAppState, SceUInt32 buildVersion);
SceInt32 sceAppMgrLoadExec(const char *appPath, char *const argv[], const SceAppMgrLoadExecOptParam *optParam);

BRIDGE_DECL(_sceAppMgrGetAppState)
BRIDGE_DECL(sceAppMgrAcidDirSet)
BRIDGE_DECL(sceAppMgrAcquireSoundOutExclusive3)
BRIDGE_DECL(sceAppMgrAddContAddMount)
BRIDGE_DECL(sceAppMgrAddContMount)
BRIDGE_DECL(sceAppMgrAppDataMount)
BRIDGE_DECL(sceAppMgrAppDataMountById)
BRIDGE_DECL(sceAppMgrAppMount)
BRIDGE_DECL(sceAppMgrAppParamGetInt)
BRIDGE_DECL(sceAppMgrAppParamGetString)
BRIDGE_DECL(sceAppMgrAppParamSetString)
BRIDGE_DECL(sceAppMgrAppUmount)
BRIDGE_DECL(sceAppMgrBgdlGetQueueStatus)
BRIDGE_DECL(sceAppMgrCaptureFrameBufDMACByAppId)
BRIDGE_DECL(sceAppMgrCaptureFrameBufIFTUByAppId)
BRIDGE_DECL(sceAppMgrCheckRifGD)
BRIDGE_DECL(sceAppMgrContentInstallPeriodStart)
BRIDGE_DECL(sceAppMgrContentInstallPeriodStop)
BRIDGE_DECL(sceAppMgrConvertVs0UserDrivePath)
BRIDGE_DECL(sceAppMgrDeclareShellProcess2)
BRIDGE_DECL(sceAppMgrDestroyAppByName)
BRIDGE_DECL(sceAppMgrDrmClose)
BRIDGE_DECL(sceAppMgrDrmOpen)
BRIDGE_DECL(sceAppMgrForceUmount)
BRIDGE_DECL(sceAppMgrGameDataMount)
BRIDGE_DECL(sceAppMgrGetAppInfo)
BRIDGE_DECL(sceAppMgrGetAppMgrState)
BRIDGE_DECL(sceAppMgrGetAppParam)
BRIDGE_DECL(sceAppMgrGetAppParam2)
BRIDGE_DECL(sceAppMgrGetBootParam)
BRIDGE_DECL(sceAppMgrGetBudgetInfo)
BRIDGE_DECL(sceAppMgrGetCoredumpStateForShell)
BRIDGE_DECL(sceAppMgrGetCurrentBgmState)
BRIDGE_DECL(sceAppMgrGetCurrentBgmState2)
BRIDGE_DECL(sceAppMgrGetDevInfo)
BRIDGE_DECL(sceAppMgrGetFgAppInfo)
BRIDGE_DECL(sceAppMgrGetIdByName)
BRIDGE_DECL(sceAppMgrGetMediaTypeFromDrive)
BRIDGE_DECL(sceAppMgrGetMediaTypeFromDriveByPid)
BRIDGE_DECL(sceAppMgrGetMountProcessNum)
BRIDGE_DECL(sceAppMgrGetNameById)
BRIDGE_DECL(sceAppMgrGetPfsDrive)
BRIDGE_DECL(sceAppMgrGetPidListForShell)
BRIDGE_DECL(sceAppMgrGetRawPath)
BRIDGE_DECL(sceAppMgrGetRawPathOfApp0ByAppIdForShell)
BRIDGE_DECL(sceAppMgrGetRawPathOfApp0ByPidForShell)
BRIDGE_DECL(sceAppMgrGetRecommendedScreenOrientation)
BRIDGE_DECL(sceAppMgrGetRunningAppIdListForShell)
BRIDGE_DECL(sceAppMgrGetSaveDataInfo)
BRIDGE_DECL(sceAppMgrGetSaveDataInfoForSpecialExport)
BRIDGE_DECL(sceAppMgrGetStatusByAppId)
BRIDGE_DECL(sceAppMgrGetStatusById)
BRIDGE_DECL(sceAppMgrGetStatusByName)
BRIDGE_DECL(sceAppMgrGetSystemDataFilePlayReady)
BRIDGE_DECL(sceAppMgrGetUserDirPath)
BRIDGE_DECL(sceAppMgrGetUserDirPathById)
BRIDGE_DECL(sceAppMgrGetVs0UserDataDrive)
BRIDGE_DECL(sceAppMgrGetVs0UserModuleDrive)
BRIDGE_DECL(sceAppMgrInitSafeMemoryById)
BRIDGE_DECL(sceAppMgrInstallDirMount)
BRIDGE_DECL(sceAppMgrIsCameraActive)
BRIDGE_DECL(sceAppMgrLaunchAppByName)
BRIDGE_DECL(sceAppMgrLaunchAppByName2)
BRIDGE_DECL(sceAppMgrLaunchAppByName2ForShell)
BRIDGE_DECL(sceAppMgrLaunchAppByName2ndStage)
BRIDGE_DECL(sceAppMgrLaunchAppByNameForShell)
BRIDGE_DECL(sceAppMgrLaunchAppByPath4)
BRIDGE_DECL(sceAppMgrLaunchAppByUri)
BRIDGE_DECL(sceAppMgrLaunchAppByUri2)
BRIDGE_DECL(sceAppMgrLaunchVideoStreamingApp)
BRIDGE_DECL(sceAppMgrLoadExec)
BRIDGE_DECL(sceAppMgrLoadSaveDataSystemFile)
BRIDGE_DECL(sceAppMgrLoopBackFormat)
BRIDGE_DECL(sceAppMgrLoopBackMount)
BRIDGE_DECL(sceAppMgrMmsMount)
BRIDGE_DECL(sceAppMgrOverwriteLaunchParamForShell)
BRIDGE_DECL(sceAppMgrPeekLaunchParamForShell)
BRIDGE_DECL(sceAppMgrPhotoMount)
BRIDGE_DECL(sceAppMgrPhotoUmount)
BRIDGE_DECL(sceAppMgrPspSaveDataGetParams)
BRIDGE_DECL(sceAppMgrPspSaveDataRead)
BRIDGE_DECL(sceAppMgrPspSaveDataRootMount)
BRIDGE_DECL(sceAppMgrReceiveEvent)
BRIDGE_DECL(sceAppMgrReceiveEventNum)
BRIDGE_DECL(sceAppMgrReceiveNotificationRequestForShell)
BRIDGE_DECL(sceAppMgrReceiveShellEvent)
BRIDGE_DECL(sceAppMgrReceiveSystemEvent)
BRIDGE_DECL(sceAppMgrSaveDataAddMount)
BRIDGE_DECL(sceAppMgrSaveDataDataRemove)
BRIDGE_DECL(sceAppMgrSaveDataDataRemove2)
BRIDGE_DECL(sceAppMgrSaveDataDataSave)
BRIDGE_DECL(sceAppMgrSaveDataDataSave2)
BRIDGE_DECL(sceAppMgrSaveDataGetQuota)
BRIDGE_DECL(sceAppMgrSaveDataMount)
BRIDGE_DECL(sceAppMgrSaveDataSlotCreate)
BRIDGE_DECL(sceAppMgrSaveDataSlotDelete)
BRIDGE_DECL(sceAppMgrSaveDataSlotFileClose)
BRIDGE_DECL(sceAppMgrSaveDataSlotFileGetParam)
BRIDGE_DECL(sceAppMgrSaveDataSlotFileOpen)
BRIDGE_DECL(sceAppMgrSaveDataSlotGetParam)
BRIDGE_DECL(sceAppMgrSaveDataSlotGetStatus)
BRIDGE_DECL(sceAppMgrSaveDataSlotInit)
BRIDGE_DECL(sceAppMgrSaveDataSlotSetParam)
BRIDGE_DECL(sceAppMgrSaveDataSlotSetStatus)
BRIDGE_DECL(sceAppMgrSaveDataUmount)
BRIDGE_DECL(sceAppMgrSendNotificationRequest)
BRIDGE_DECL(sceAppMgrSendParam)
BRIDGE_DECL(sceAppMgrSendSystemEvent)
BRIDGE_DECL(sceAppMgrSendSystemEvent2)
BRIDGE_DECL(sceAppMgrSetBackRenderPortOwner)
BRIDGE_DECL(sceAppMgrSetBgmProxyApp)
BRIDGE_DECL(sceAppMgrSetNetworkDisconnectionWarningDialogState)
BRIDGE_DECL(sceAppMgrSetPowerSaveMode)
BRIDGE_DECL(sceAppMgrSetRecommendedScreenOrientationForShell)
BRIDGE_DECL(sceAppMgrSetShellScreenOrientation)
BRIDGE_DECL(sceAppMgrSetSystemDataFile)
BRIDGE_DECL(sceAppMgrSetSystemDataFilePlayReady)
BRIDGE_DECL(sceAppMgrSystemParamDateTimeGetConf)
BRIDGE_DECL(sceAppMgrSystemParamGetInt)
BRIDGE_DECL(sceAppMgrSystemParamGetString)
BRIDGE_DECL(sceAppMgrThemeDataMount)
BRIDGE_DECL(sceAppMgrTrophyMount)
BRIDGE_DECL(sceAppMgrTrophyMountById)
BRIDGE_DECL(sceAppMgrUmount)
BRIDGE_DECL(sceAppMgrUmountByPid)
BRIDGE_DECL(sceAppMgrUpdateSaveDataParam)
BRIDGE_DECL(sceAppMgrWorkDirMount)
BRIDGE_DECL(sceAppMgrWorkDirMountById)
