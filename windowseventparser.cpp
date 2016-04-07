#include "windowseventparser.h"
#include <ctime>
#include <iostream>

#include <winevt.h>
#include <windows.h>

#include <string>
#include <list>

#include "common.h"


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
    Event(EventID::SECURITY_OPERATION_1, L"Microsoft-Windows-Security-Auditing")/*,
    Event(EventID::SECURITY_OPERATION_2, L"Microsoft-Windows-Security-Auditing")*/
};


WindowsEventParser::WindowsEventParser(ParserFlag flags):
    m_flags(flags)
{

}

time_t WindowsEventParser::getLogOnTimeByDate(const time_t &date)
{
    list<time_t> times;
    int status = -1;

    if(m_flags & ParserFlag::USE_SYSTEM_EVENTS)
    {
        status = getEventTimesByDate(date, SYSTEM_EVENTS_START, L"System", &times);
        if(status == ERROR_SUCCESS && times.size())
            return times.front();
    }
    if(m_flags & ParserFlag::USE_SECURITY_EVENTS)
    {
        status = getEventTimesByDate(date, SECURITY_EVENTS, L"Security", &times);
        if(status == ERROR_SUCCESS && times.size())
            return times.front();
    }

    wcout<<L"Failed to Get Log On Time for date: "<<ctime(&date);
    return 0;
}

time_t WindowsEventParser::getLogOffTimeByDate(const time_t &date)
{
    list<time_t> times;
    int status = -1;

    if(m_flags & ParserFlag::USE_SYSTEM_EVENTS)
    {
        status = getEventTimesByDate(date, SYSTEM_EVENTS_FINISH, L"System", &times);
        if(status == ERROR_SUCCESS && times.size())
            return times.back();
    }
    if(m_flags & ParserFlag::USE_SECURITY_EVENTS)
    {
        status = getEventTimesByDate(date, SECURITY_EVENTS, L"Security", &times);
        if(status == ERROR_SUCCESS && times.size())
            return times.back();
    }

    wcout<<L"Failed to Get Log Off Time for date: "<<ctime(&date);
    return 0;
}

DWORD WindowsEventParser::getEventTimesByDate(const time_t &date, const std::list<Event> &events, const std::wstring &path, std::list<time_t> *times)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

    struct tm dateTM, dateTMTo;
    //TODO check for errors
    localtime_s(&dateTM, &date);
    auto dateTo = date + 3600*24; // Add day in seconds 3600 seconds in hour * 24 hours
    localtime_s(&dateTMTo, &dateTo);

    SYSTEMTIME stFrom, stTo;
    stFrom.wSecond = dateTM.tm_sec;
    stFrom.wMinute = dateTM.tm_min;
    stFrom.wHour = dateTM.tm_hour;
    stFrom.wDay = dateTM.tm_mday;
    stFrom.wMonth = dateTM.tm_mon + 1;
    stFrom.wYear = dateTM.tm_year + 1900;
    stFrom.wDayOfWeek = 0;

    stTo.wSecond = dateTMTo.tm_sec;
    stTo.wMinute = dateTMTo.tm_min;
    stTo.wHour = dateTMTo.tm_hour;
    stTo.wDay = dateTMTo.tm_mday;
    stTo.wMonth = dateTMTo.tm_mon + 1;
    stTo.wYear = dateTMTo.tm_year + 1900;
    stTo.wDayOfWeek = 0;



    //stTo = add(stFrom, 3600*24); // Add day

    wstring timeParamFrom, timeParamTo;
    timeParamFrom += L"'";
    timeParamFrom += to_wstring(stFrom.wYear) + L"-";
    if(stFrom.wMonth < 10)
        timeParamFrom += L'0';
    timeParamFrom += to_wstring(stFrom.wMonth) + L"-";
    if(stFrom.wDay < 10)
        timeParamFrom += L'0';
    timeParamFrom += to_wstring(stFrom.wDay);
    timeParamFrom += L"T00:00:000Z'";

    timeParamTo += L"'";
    timeParamTo += to_wstring(stTo.wYear) + L"-";
    if(stTo.wMonth < 10)
        timeParamTo += L'0';
    timeParamTo += to_wstring(stTo.wMonth) + L"-";
    if(stTo.wDay < 10)
        timeParamTo += L'0';
    timeParamTo += to_wstring(stTo.wDay);
    timeParamTo += L"T00:00:000Z'";


    wstring sEventID = L"(";
    if(!events.size())
    {
        wcout << "No events passed" << endl;
        return ERROR_NO_EVENTS;
    }

    int counter = 0;
    for(const auto &event: events)
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

//    auto sPwsQuery = wstring(L"Event/System[EventID=");
//    sPwsQuery += sEventID;
//    sPwsQuery += L" and TimeCreated[@SystemTime >= ";
//    sPwsQuery += timeParamFrom;
//    sPwsQuery += L" and ";
//    sPwsQuery += L"@SystemTime <= ";
//    sPwsQuery += timeParamTo;
//    sPwsQuery += L"]]";

    auto sPwsQuery = wstring(L"Event/System[");
    sPwsQuery += sEventID;
    sPwsQuery += L" and TimeCreated[@SystemTime >= ";
    sPwsQuery += timeParamFrom;
    sPwsQuery += L" and ";
    sPwsQuery += L"@SystemTime <= ";
    sPwsQuery += timeParamTo;
    sPwsQuery += L"]]";


    //sPwsQuery = L"Event/System[((EventID=42 and Provider[@Name='Microsoft-Windows-Kernel-Power']) or (EventID=12 and Provider[@Name='Microsoft-Windows-Kernel-General'])) and TimeCreated[@SystemTime >= '2016-03-01T00:00:000Z' and @SystemTime <= '2016-03-02T00:00:000Z']]";
    //sPwsQuery = L"Event/System[EventID=1]";
    //wcout <<"Query: "<<sPwsQuery<<endl;

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

DWORD WindowsEventParser::getResults(EVT_HANDLE hResults, list<time_t> *times)
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
            //else
                //wcout<<L"No More events "<<status<<endl;
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

DWORD WindowsEventParser::getEventSystemTime(EVT_HANDLE hEvent, time_t *eventSystemTime)
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


    std::tm tm;

    tm.tm_sec = st.wSecond;
    tm.tm_min = st.wMinute;
    tm.tm_hour = st.wHour;
    tm.tm_mday = st.wDay;
    tm.tm_mon = st.wMonth - 1;
    tm.tm_year = st.wYear - 1900;
    tm.tm_isdst = -1;

    *eventSystemTime = std::mktime(&tm);

cleanup:

    if (hContext)
        EvtClose(hContext);

    if (pRenderedValues)
        free(pRenderedValues);

    return status;
}


