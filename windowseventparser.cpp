#include "windowseventparser.h"
#include <ctime>
#include <iostream>

#include <winevt.h>
#include <windows.h>

#include <string>
#include <list>

#include "common.h"

#define LOGD if(m_debugOutput) wcout

using std::list;
using std::wstring;
using std::to_wstring;
using std::wcout;
using std::endl;

const list<Event> WindowsEventParser::SYSTEM_EVENTS_START = {
    Event(EventID::SLEEP_OFF, L"Microsoft-Windows-Power-Troubleshooter"),
    Event(EventID::TURN_ON, L"Microsoft-Windows-Kernel-General")
};

const list<Event> WindowsEventParser::SYSTEM_EVENTS_FINISH = {
    Event(EventID::SLEEP_ON, L"Microsoft-Windows-Kernel-Power"),
    Event(EventID::TURN_OFF, L"User32")
};

const std::list<Event> WindowsEventParser::SECURITY_EVENTS = {
    Event(EventID::SECURITY_OPERATION_1, L"Microsoft-Windows-Security-Auditing"),
    Event(EventID::SECURITY_OPERATION_2, L"Microsoft-Windows-Security-Auditing"),
    Event(EventID::SECURITY_OPERATION_3, L"Microsoft-Windows-Security-Auditing")
};

//int WindowsEventParser::m_flags = ;
//bool WindowsEventParser::m_debugOutput ;
//std::wstring WindowsEventParser::m_customEventsStartPath = L"";
//std::wstring WindowsEventParser::m_customEventsFinishPath = L"";

void WindowsEventParser::setCustomEventStart(const std::list<Event> &lst, const std::wstring& path)
{
    if(lst.size() && !path.empty())
    {
        m_customEventsStart = lst;
        m_customEventsStartPath = path;

        if(!(m_flags & ParserFlag::USE_CUSTOM_EVENTS))
            m_flags |= ParserFlag::USE_CUSTOM_EVENTS;
    }
}
void WindowsEventParser::setCustomEventFinish(const std::list<Event> &lst, const std::wstring& path)
{
    if(lst.size() && !path.empty())
    {
        m_customEventsFinish = lst;
        m_customEventsFinishPath = path;
        if(!(m_flags & ParserFlag::USE_CUSTOM_EVENTS))
            m_flags |= ParserFlag::USE_CUSTOM_EVENTS;
    }
}

time_t WindowsEventParser::getLogOnTimeByDate(const time_t &date) const
{
    return getLogTimeBase(date, true);
}

time_t WindowsEventParser::getLogOffTimeByDate(const time_t &date) const
{
    return getLogTimeBase(date, false);
}

time_t WindowsEventParser::getLogTimeBase(const time_t &date,  bool isLogOn) const
{
    list<time_t> times;
    int status = -1;
    wstring path = L"";
    const list<Event> *events;
    if(m_flags & ParserFlag::USE_SYSTEM_EVENTS)
    {
        path = L"System";
        events = isLogOn?&SYSTEM_EVENTS_START:&SYSTEM_EVENTS_FINISH;
        status = getEventTimesByDate(date, events, path, &times);
        if(status == ERROR_SUCCESS && times.size())
            return isLogOn?times.front():times.back();
        else
        {
            LOGD<<L"getEventTimesByDate Failed By System Events" << endl;
            if(!times.size())
                LOGD << L"Times are empty" << endl;
            if(status != ERROR_SUCCESS)
                LOGD << L"Error: " << status << endl;
        }
    }
    if(m_flags & ParserFlag::USE_SECURITY_EVENTS)
    {
        path = L"Security";
        events = &SECURITY_EVENTS;
        status = getEventTimesByDate(date, events, path, &times);
        if(status == ERROR_SUCCESS && times.size())
            return isLogOn?times.front():times.back();
        else
        {
            LOGD<<L"getEventTimesByDate Failed By Security Events" << endl;
            if(!times.size())
                LOGD << L"Times are empty" << endl;
            if(status != ERROR_SUCCESS)
                LOGD << L"Error: " << status << endl;
        }
    }
    if(m_flags & ParserFlag::USE_CUSTOM_EVENTS)
    {
        path = isLogOn?m_customEventsStartPath: m_customEventsFinishPath;
        events = isLogOn?&m_customEventsStart:&m_customEventsFinish;
        status = getEventTimesByDate(date, events, path, &times);
        if(status == ERROR_SUCCESS && times.size())
            return isLogOn?times.front():times.back();
        else
        {
            LOGD<<L"getEventTimesByDate Failed By Custom Events" << endl;
            if(!times.size())
                LOGD << L"Times are empty" << endl;
            if(status != ERROR_SUCCESS)
                LOGD << L"Error: " << status << endl;
        }
    }
    wcout<<L"Failed to Get Log " << (isLogOn?L"On":L"Off") << L"Time for date: "<<ctime(&date);
    return 0;
}

DWORD WindowsEventParser::getEventTimesByDate(const time_t &dateFrom, const std::list<Event> *events, const std::wstring &path, std::list<time_t> *times) const
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

    struct tm dateTMFrom, dateTMTo;
    //TODO check for errors
    localtime_s(&dateTMFrom, &dateFrom);
    auto dateTo = dateFrom + 3600*24; // Add day in seconds 3600 seconds in hour * 24 hours
    localtime_s(&dateTMTo, &dateTo);

    //stTo = add(stFrom, 3600*24); // Add day

    auto timeParamFromTM = [](const tm & dateTM) {
        wstring timeParam = L"";
        timeParam += L"'";
        timeParam += to_wstring(dateTM.tm_year + 1900) + L"-";
        if(dateTM.tm_mon + 1 < 10)
            timeParam += L'0';
        timeParam += to_wstring(dateTM.tm_mon + 1) + L"-";
        if(dateTM.tm_mday < 10)
            timeParam += L'0';
        timeParam += to_wstring(dateTM.tm_mday);
        timeParam += L"T00:00:000Z'";
        return timeParam;
    };

    wstring timeParamFrom = timeParamFromTM(dateTMFrom), timeParamTo = timeParamFromTM(dateTMTo);
    wstring sEventID = L"(";
    if(!events->size())
    {
        wcout << "No events passed" << endl;
        return ERROR_NO_EVENTS;
    }

    int counter = 0;
    for(const auto &event: *events)
    {
        if(counter++)
        {
            sEventID += L" or ";
        }
        sEventID += L"(EventID=";
        sEventID += to_wstring(static_cast<unsigned int>(event.id));
        sEventID += L" and ";
        sEventID += L"Provider[@Name='";
        sEventID += event.source;
        sEventID += L"'])";
    }
    sEventID += L")";

    auto sPwsQuery = wstring(L"Event/System[");
    sPwsQuery += sEventID;
    sPwsQuery += L" and TimeCreated[@SystemTime >= ";
    sPwsQuery += timeParamFrom;
    sPwsQuery += L" and ";
    sPwsQuery += L"@SystemTime <= ";
    sPwsQuery += timeParamTo;
    sPwsQuery += L"]]";

    LOGD <<"Query: "<<sPwsQuery<<endl;

    LPCWSTR pwsPath = path.c_str();
    LPCWSTR pwsQuery = sPwsQuery.c_str();
    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (NULL == hResults)
    {        
        status = GetLastError();

        if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
            wcout << L"The channel was not found." << endl;
        else if (ERROR_EVT_INVALID_QUERY == status)
            // You can call the EvtGetExtendedStatus function to try to get
            // additional information as to what is wrong with the query.
            wcout << L"The query is not valid." << endl;
        else
            wcout << L"EvtQuery failed with " << status << "." << endl;
        goto clean;
    }    
    getResults(hResults, times);
clean:
    if (hResults)
    {        
        EvtClose(hResults);
    }    
    return status;
}

DWORD WindowsEventParser::getResults(EVT_HANDLE hResults, list<time_t> *times) const
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;
    while (true)
    {
        // Get a block of events from the result set.
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned))
        {
            if ( ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }
            else
                LOGD<<L"No More events "<<status<<endl;
            goto cleanup;
        }

        // For each event, call the PrintEvent function which renders the
        // event for display. PrintEvent is shown in RenderingEvents.

        for (DWORD i = 0; i < dwReturned; i++)
        {
            time_t time;
            if (ERROR_SUCCESS == (status = getEventSystemTime(hEvents[i], &time)))
            {
                //wcout<<"GOOD getResults"<<endl;
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
                times->push_front(time);
            }
            else
            {
                wcout<<"Error getResults"<<endl;
                goto cleanup;
            }
        }
    }

    if(times->size())
        times->sort();

cleanup:   
    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}

DWORD WindowsEventParser::getEventSystemTime(EVT_HANDLE hEvent, time_t *eventSystemTime) const
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME st;
    FILETIME ft, lt;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (NULL == hContext)
    {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pRenderedValues)
            {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    //wprintf(L"ullTimeStamp: %I64u\n", ullTimeStamp);
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    //wprintf(L"high: %I64u\n", ft.dwHighDateTime);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

    FileTimeToLocalFileTime(&ft, &lt);
    FileTimeToSystemTime(&lt, &st);

    *eventSystemTime = getTimeFromSystemTime(st);

cleanup:

    if (hContext)
        EvtClose(hContext);

    if (pRenderedValues)
        free(pRenderedValues);

    return status;
}


