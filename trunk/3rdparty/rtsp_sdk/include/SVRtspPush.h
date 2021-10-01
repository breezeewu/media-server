//
//  SVRtspPush.h
//  SVRtspPush 
//
//  Created by Juno on 2019/6/4.
//  Copyright © 2019年 Juno. All rights reserved.
//
#ifndef SVRtspPush_h
#define SVRtspPush_h
#define CALLBACK
//#include "SVRtspPushDefine.h"
//#pragma once
typedef enum E_Event_Code{ //event type
    E_Event_Code_Null                               =   0x00,
    E_Event_Code_Server_Connect_Processing          =   0x01,
    E_Event_Code_Server_Connect_TimeOut             =   0x02,
    E_Event_Code_Server_Connect_Succeed             =   0x03,
    E_Event_Code_Server_Connect_Failed              =   0x04,
    E_Event_Code_Server_Video_Sps_Pps_DataError     =   0x05,
    E_Event_Code_Server_Audio_Adts_DataError        =   0x06,
    E_Event_Code_Server_Is_Connect                  =   0x07,
    E_Event_Code_Server_Disconnect                  =   0x08,
    E_Event_Code_Server_EmptyUrl                    =   0x09,
    E_Event_Code_Server_InvalidUrl                  =   0x0a,
    E_Event_Code_Server_InvalidParameter            =   0x0b,
    E_Event_Code_Server_SendVideoFailure            =   0x0c,
    E_Event_Code_Server_SendAudioFailure            =   0x0d,
    E_Event_Code_Server_SendVideoTimeOut            =   0x0e,
    E_Event_Code_Server_SendAudioTimeOut            =   0x0f,
    E_Event_Code_Server_Connect_Create_Failed       =   0xa1,
    E_Event_Code_Server_Connect_Dns_Resovle_Failed  =   0xa2,
    E_Event_Code_Server_Connect_Hand_Shake_Failed   =   0xa3,
    E_Event_Code_Server_Connect_APP_Failed          =   0xa4,
    E_Event_Code_Server_Connect_Stream_Failed       =   0xa5,
    E_Event_Code_Server_Connect_Set_TimeOut_Failed  =   0xa6,
    E_Event_Code_Server_Delete_OBJ_Success          =   0xa7,
    E_Event_Code_Server_Recv_Video_Data_Error       =   0xa8,
    E_Event_Code_Server_Recv_Audio_Data_Error       =   0xa9,
    E_Event_Code_Server_SendVideoDVDSPFailure       =   0xb1,
    E_Event_Code_Server_SendVideoPPSFailure         =   0xb2,
    E_Event_Code_Server_SendVideoSPSFailure         =   0xb3,
    E_Event_Code_Server_SendMediaPlay               =   0xb4,
    E_Event_Code_Server_SendMediaPause              =   0xb5,
    
}E_Event_Code;

typedef int (CALLBACK* Event_CallBack)(int nUserID, E_Event_Code eHeaderEventCode);

#define SVRtspPush_API  extern "C"

/**
 * 仅初始化一次相关的资源
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Initialize();

/**
 * 仅释放一次相关的资源
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_UnInitialize();

/**
 * 发送H264数据
 * @param pLogPath log日志本地存储路径
 * @param nLogLevel 日志等级
 * @param nLogFlag 日志输出方式
 * 日志支持同时输出到控制台和文件,设置方式为:SV_LOG_OUTPUT_MODE_CONSOLE|SV_LOG_OUTPUT_MODE_FILE
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Init_log(const char* pLogPath, int nLogLevel, int nLogFlag);

/**
 * 初始化并连接到rtsp服务器
 * @param url 服务器上对应webapp的地址
 * @成功则返回userID , 失败则返回 -1
 */
SVRtspPush_API long SVRtspPush_API_Connect(const char* pUrl, Event_CallBack pEventFunction);

/**
 * 发送H264数据
 * @param userID 实例用户标识ID
 * @param data 存储数据帧内容
 * @param size 数据帧的大小
 * @param isKey 关键帧 1，反之 0
 * @param nTimeStamp 当前帧的显示时间戳
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Send_VideoPacket(long userID, char* data,unsigned int size, unsigned int nTimeStamp);

/**
 * 发送音频数据 adts+raw data
 * @param userID 实例用户标识ID
 * @param data 音频帧信息
 * @param len  音频帧信息长度
 * @param nTimeStamp 当前帧的时间戳
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Send_AudioPacket(long userID, char* data, unsigned int len, unsigned int nTimeStamp);

/**
 * @param userID 实例用户标识ID
 * rtsp 连接状态
 * @成功则返回 1 , 失败则返回 0
 */
SVRtspPush_API int SVRtspPush_API_RtspIsConnected(long userID);

/**
 * @param userID 实例用户标识ID
 * 断开连接，释放相关的资源
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Close(long userID);

/**
 * 获取版本信息
 * @成功则返回 0 , 失败则返回 -1
 */
SVRtspPush_API int SVRtspPush_API_Version(char* szVersionJson);

#endif

