#ifndef __GLOG__
#define __GLOG__


#include <sstream>
#include <fstream>
#include <string.h>
#include <string>
#include <iostream>
#include <time.h>
#include <stdio.h>
#include <iomanip>

#include <list>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>

//extern int g_LogLevel;

enum db_LogLevelConstant {
    db_LOGLEVEL_DEBUG,
    db_LOGLEVEL_INFO,
    db_LOGLEVEL_WARN,
    db_LOGLEVEL_ERROR,
    db_LOGLEVEL_TRACE
};


struct db_tagLogData {
//    static std::atomic<long long> num;
//
//    tagLogData() {
//        num++;
//    }
//
//    ~tagLogData() {
//        num--;
//    }

    int nLevel;
    std::string strLog;
    std::string strTime;
};


class db_CLogThread {
public:
    db_CLogThread();

    ~db_CLogThread();

    bool _PutLog(int level, const char *str);

    void _StartLog(const char *prefix, bool log2file, int filesize);

    void _StopLog();

    bool _IsRun();

    void _SetLogLevel(int nLevel);

    int _GetLogLevel();

public:
    static void InitLogger(const char *prefix, bool log2file = true, int level = db_LOGLEVEL_INFO,
                           int filesize = 512);

    static void DestroyLogger();

    static void WriteLog(int level, const char *str);

    static void SetLogLevel(int level);

    static int GetLogLevel();

private:
    void Run();

    void CreateMonthDir();

private:

    std::list<std::unique_ptr<db_tagLogData >> m_Queue;
    std::list<std::unique_ptr<db_tagLogData >> m_QueueOut;
    bool m_bStop;


    int m_nMaxLogFileSize;
    std::string m_sLogFilrPrefix;
    bool m_bLog2File;

    bool m_bDirCreated;
    std::string m_sLogRootDir;
    std::string m_sLogDir;
    std::fstream m_fp;
    int m_nDate;
    int m_nMonth;

    int m_nLogFileSize;
    int g_LogLevel = db_LOGLEVEL_INFO;

    std::mutex mux;
    static db_CLogThread * db_cLogThread_ptr;
};

static db_CLogThread g_log;


#define db_TOOLWRITELOG(level, os) {\
    if (db_CLogThread::GetLogLevel() <= level)\
    {\
        std::ostringstream logoss;\
        logoss<<"["<<__PRETTY_FUNCTION__<<"]"<<os;\
        db_CLogThread::WriteLog(level, (const char *)logoss.str().c_str() ); \
    }\
}

#define db_TOOLWRITEERRLOG(level, os, errcode) {\
    if (db_CLogThread::GetLogLevel() <= level)\
    {\
        std::ostringstream codeos;\
        codeos << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << errcode;\
        std::ostringstream logoss;\
        logoss<<"["<<__PRETTY_FUNCTION__<<"]["<<codeos.str()<<"]"<<os;\
        db_CLogThread::WriteLog(level, (const char *)logoss.str().c_str() ); \
    }\
}

#define T_LOGI(os) db_TOOLWRITELOG( db_LOGLEVEL_INFO, os )
#define T_LOGD(os) db_TOOLWRITELOG( db_LOGLEVEL_DEBUG, os )
#define T_LOGW(os) db_TOOLWRITELOG( db_LOGLEVEL_WARN, os )
#define T_LOGE(os) db_TOOLWRITELOG( db_LOGLEVEL_ERROR, os )
#define T_LOGT(os) db_TOOLWRITELOG( db_LOGLEVEL_TRACE, os )


#endif