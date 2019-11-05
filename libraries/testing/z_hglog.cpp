#include <stdlib.h>
#include <iostream>
#include <thread>
#include <list>

#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/prctl.h>

#include <eosio/testing/z_hglog.hpp>


//std::atomic<long long> tagLogData::num = {0};

db_CLogThread *db_CLogThread::db_cLogThread_ptr = {nullptr};


db_CLogThread::db_CLogThread() {
    m_bStop = true;
    db_cLogThread_ptr = &g_log;
}

db_CLogThread::~db_CLogThread() {
    _StopLog();
}

bool db_CLogThread::_PutLog(int level, const char *str) {
    std::lock_guard<std::mutex> lock(mux);

    auto ld = std::make_unique<db_tagLogData>();
    ld->nLevel = level;
    ld->strLog = str;

    if (m_Queue.size() > 80000)
        m_Queue.pop_front();

    m_Queue.push_back(std::move(ld));
    return true;
}

void db_CLogThread::_StartLog(const char *prefix, bool log2file, int filesize) {
    if (!m_bStop) return;

    m_bLog2File = log2file;
    m_sLogFilrPrefix = prefix;
    m_nMaxLogFileSize = filesize * 1024 * 1024;
    m_nLogFileSize = 0;

    m_sLogRootDir = "./log/";
    CreateMonthDir();

    m_bStop = false;

    new std::thread([this]() {
        Run();
    });
}

void db_CLogThread::_StopLog() {
    if (m_bStop)return;

    if (m_fp.is_open()) {
        m_fp.close();
    }
}

bool db_CLogThread::_IsRun() { return !m_bStop; }

void db_CLogThread::_SetLogLevel(int nLevel) { g_LogLevel = nLevel; }

int db_CLogThread::_GetLogLevel() { return g_LogLevel; }

void db_CLogThread::Run() {
    prctl(PR_SET_NAME, "DB_LOG");

    while (!m_bStop) {
        {
            std::lock_guard<std::mutex> lock(mux);
            std::swap(m_Queue, m_QueueOut);
        }

        if (m_QueueOut.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
            continue;
        }

        while (!m_QueueOut.empty()) {
            auto &ld = m_QueueOut.front();
            // auto size = m_QueueOut.size();

            //拼内容
            std::ostringstream ss;
            //ss << ld.strTime;
            ss << time(0);
            switch (ld->nLevel) {
                case db_LOGLEVEL_DEBUG:
                    ss << "[DEBUG]";
                    break;
                case db_LOGLEVEL_INFO:
                    ss << "[INFO]";
                    break;
                case db_LOGLEVEL_WARN:
                    ss << "[WARN]";
                    break;
                case db_LOGLEVEL_ERROR:
                    ss << "[ERROR]";
                    break;
                case db_LOGLEVEL_TRACE:
                    ss << "[TRACE]";
                    break;
                default:
                    ss << "[OTHER]";
                    break;
            }
            ss << ld->strLog;

            if (!m_bLog2File) {
                std::cout << ss.str().c_str() << std::endl;
                continue;
            }

            //检查目录
            time_t now = time(NULL);
            struct tm t = {0};
            localtime_r(&now, &t);

            bool bMonthChange = false;
            if (t.tm_mon != m_nMonth) {
                CreateMonthDir();
                bMonthChange = true;
            }

            if (!m_bDirCreated) {
                std::cerr << "CreateMonthDir fail log stop:dir=" << m_sLogDir << ",err=" << errno << std::endl;
                m_bStop = true;
                break;
            }
            //新建文件
            if (!m_fp.is_open() || m_nDate != t.tm_mday || bMonthChange ||
                m_nLogFileSize + (int) ss.str().size() > m_nMaxLogFileSize) {
                if (m_fp.is_open()) {
                    m_fp.close();
                }

                char file[255];
                sprintf(file, "%s%s_%02d-%02d-%02d-%02d%02d%02d.log", m_sLogDir.c_str(), m_sLogFilrPrefix.c_str(),
                        t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
                m_fp.open(file, std::ios::out | std::ios::app);
                if (!m_fp.is_open()) {
                    fprintf(stderr, "failed to open logfile. filename=%s, errno=%d, strerr=%s\n", file, errno,
                            strerror(errno));
                    //可能是日志目录被删掉了,重新创建,但这条日志会扔掉
                    if (errno == ENOENT || errno == EACCES) //errno==2 ||errno==13
                        CreateMonthDir();
                    continue;
                }
                m_nDate = t.tm_mday;
                m_nLogFileSize = 0;
            }
            //写入文件
            m_fp << ss.str() << std::endl;
            m_nLogFileSize += ss.str().size();
            m_fp.flush();
            m_QueueOut.pop_front();
        }
    }
}


void db_CLogThread::CreateMonthDir() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char subDir[255];

    m_bDirCreated = false;
    sprintf(subDir, "%s%d-%d/", m_sLogRootDir.c_str(), t->tm_year + 1900, t->tm_mon + 1);
    m_sLogDir = subDir;

    mkdir(m_sLogRootDir.c_str(), 0755);
    mkdir(m_sLogDir.c_str(), 0755);
    m_bDirCreated = true;
    m_nMonth = t->tm_mon;
}

void db_CLogThread::InitLogger(const char *prefix, bool log2file, int level, int filesize) {
    if (db_cLogThread_ptr == nullptr) return;

    if (db_cLogThread_ptr->_IsRun()) return;

    db_cLogThread_ptr->SetLogLevel(level);
    db_cLogThread_ptr->_StartLog(prefix, log2file, filesize);
}

void db_CLogThread::DestroyLogger() {
    if (db_cLogThread_ptr == nullptr) return;
    db_cLogThread_ptr->_StopLog();
}

void db_CLogThread::WriteLog(int level, const char *str) {
    if (db_cLogThread_ptr == nullptr) return;
    if (!db_cLogThread_ptr->_IsRun()) return;

    if (db_cLogThread_ptr->GetLogLevel() <= level) {
        if (!db_cLogThread_ptr->_PutLog(level, str))
            std::cout << str << std::endl;
    }
}

void db_CLogThread::SetLogLevel(int level) {
    if (db_cLogThread_ptr == nullptr) return;
    db_cLogThread_ptr->_SetLogLevel(level);
}

int db_CLogThread::GetLogLevel() {
    if (db_cLogThread_ptr == nullptr) return -1;

    return db_cLogThread_ptr->_GetLogLevel();
}

