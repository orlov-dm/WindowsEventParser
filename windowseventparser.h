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
enum ParserFlag { USE_SYSTEM_EVENTS = 0x1, USE_SECURITY_EVENTS = 0x2, USE_ALL = ParserFlag::USE_SECURITY_EVENTS | ParserFlag::USE_SYSTEM_EVENTS };
class WindowsEventParser
{
public:
    WindowsEventParser(ParserFlag flags = ParserFlag::USE_ALL);
    time_t getLogOnTimeByDate(const time_t &date);
    time_t getLogOffTimeByDate(const time_t &date);

protected:
    DWORD getEventTimesByDate(const time_t &date, const std::list<Event> &events, const std::wstring &path, std::list<time_t> *times);
    DWORD getResults(EVT_HANDLE hResults, std::list<time_t> *times);
    DWORD getEventSystemTime(EVT_HANDLE hEvent, time_t *eventSystemTime);

private:
    ParserFlag m_flags;
    static const unsigned int ARRAY_SIZE = 10;
    static const std::list<Event> SYSTEM_EVENTS_START;
    static const std::list<Event> SYSTEM_EVENTS_FINISH;
    static const std::list<Event> SECURITY_EVENTS;

    static const unsigned long ERROR_NO_EVENTS = 20000;
};

#endif // WINDOWSEVENTPARSER_H
