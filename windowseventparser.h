#ifndef WINDOWSEVENTPARSER_H
#define WINDOWSEVENTPARSER_H

#include <ctime>
#include <list>
#include <windows.h>
#include <winevt.h>
#include <string>

//enum class EventID { LOG_ON = /*4624*/5058, LOG_OFF = /*4634*/5061 };
enum class EventID { UNKNOWN = 0, SLEEP_ON = 42, SLEEP_OFF = 1, TURN_ON = 12, TURN_OFF = 1074, SECURITY_OPERATION_1 = 4738/*5058*/, SECURITY_OPERATION_2 = 5061};

struct Event
{
    Event(EventID id, std::wstring source):
        id(id), source(source){;}

    EventID id = EventID::UNKNOWN;
    std::wstring source = L"";
};
enum ParserFlag { USE_SYSTEM_EVENTS = 0x1, USE_SECURITY_EVENTS = 0x2, USE_CUSTOM_EVENTS = 0x4, USE_ALL = USE_SECURITY_EVENTS | USE_SYSTEM_EVENTS | USE_CUSTOM_EVENTS };
class WindowsEventParser
{
public:
    WindowsEventParser(int flags = ParserFlag::USE_ALL, bool needDebugOutput = false);
    void setCustomEventStart(const std::list<Event> &lst, const std::wstring& path);
    void setCustomEventFinish(const std::list<Event> &lst, const std::wstring& path);

    time_t getLogOnTimeByDate(const time_t &date);
    time_t getLogOffTimeByDate(const time_t &date);

protected:
    time_t getLogTimeBase(const time_t &date,  bool isLogOn);
    DWORD getEventTimesByDate(const time_t &dateFrom, const std::list<Event> *events, const std::wstring &path, std::list<time_t> *times);
    DWORD getResults(EVT_HANDLE hResults, std::list<time_t> *times);
    DWORD getEventSystemTime(EVT_HANDLE hEvent, time_t *eventSystemTime);

private:
    int m_flags; //Combination of ParseFlags    
    bool m_debugOutput = false;

    static const unsigned int ARRAY_SIZE = 10;
    static const std::list<Event> SYSTEM_EVENTS_START;
    static const std::list<Event> SYSTEM_EVENTS_FINISH;
    static const std::list<Event> SECURITY_EVENTS;

    std::list<Event> m_customEventsStart;
    std::list<Event> m_customEventsFinish;
    std::wstring m_customEventsStartPath = L"";
    std::wstring m_customEventsFinishPath = L"";

    static const unsigned long ERROR_NO_EVENTS = 20000;
};

#endif // WINDOWSEVENTPARSER_H
