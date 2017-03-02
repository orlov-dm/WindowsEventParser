#ifndef WINDOWSEVENTPARSER_H
#define WINDOWSEVENTPARSER_H

#include <ctime>
#include <list>
#include <map>
#include <windows.h>
#include <winevt.h>
#include <string>

//enum class EventID { LOG_ON = /*4624*/5058, LOG_OFF = /*4634*/5061 };
enum class EventID { UNKNOWN = 0, /*SLEEP_ON = 42, SLEEP_OFF = 1,*/
                     TURN_ON = 12, TURN_OFF = 13,
                     SEC_LOCK = 4800, SEC_UNLOCK = 4801
                   };

struct EventType
{
    EventType(EventID id = EventID::UNKNOWN, std::wstring source = L""):
        id(id), source(source){;}

    EventID id = EventID::UNKNOWN;
    std::wstring source = L"";

//    bool operator == (const EventType &second) {
//        return this->id == second.id && this->source == second.source;
//    }
};

bool operator == (const EventType &first, const EventType &second);

struct EventInfo
{
    EventInfo(EventType type = EventType(), time_t time = 0):
        type(type), time(time){;}

    EventType type;
    time_t time = 0;
};

enum ParserFlag { USE_SYSTEM_EVENTS = 0x1, USE_SECURITY_EVENTS = 0x2,  USE_ALL = USE_SECURITY_EVENTS | USE_SYSTEM_EVENTS };
class WindowsEventParser
{

protected:    
    DWORD getEventTimesByDate(const time_t &dateFrom, const time_t &dateTo, const std::list<EventType> *events, const std::wstring &path, std::map<time_t, time_t> *daysLogOns, std::map<time_t, time_t> *daysLogOffs) const;
    DWORD getResults(EVT_HANDLE hResults, const std::wstring &path, std::map<time_t, time_t> *daysLogOns, std::map<time_t, time_t> *daysLogOffs) const;
    DWORD getEventInfo(EVT_HANDLE hEvent, EventInfo *eventInfo) const;

private:
    WindowsEventParser() {}

    int m_flags = ParserFlag::USE_ALL; //Combination of ParseFlags
    bool m_debugOutput = true;

    static const unsigned int ARRAY_SIZE = 10;
    static const std::list<EventType> SYSTEM_EVENTS_START;
    static const std::list<EventType> SYSTEM_EVENTS_FINISH;
    static const std::list<EventType> SECURITY_EVENTS_START;
    static const std::list<EventType> SECURITY_EVENTS_FINISH;

    static const unsigned long ERROR_NO_EVENTS = 20000;

public:
    static WindowsEventParser &getInstance()
    {
        static WindowsEventParser instance;
        return instance;
    }

    WindowsEventParser(const WindowsEventParser&) = delete;
    void operator=(const WindowsEventParser&) = delete;

    void setFlags(int flags) { m_flags = flags; }
    void setDebugOutput(bool value) { m_debugOutput = value; }

    std::pair<std::map<time_t, time_t>, std::map<time_t, time_t>> getLogTimesByDate(const time_t &dateFrom, const time_t &dateTo) const;

};

#endif // WINDOWSEVENTPARSER_H
