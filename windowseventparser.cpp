#include "windowseventparser.h"
#include <ctime>
#include <iostream>

#include <winevt.h>
#include <windows.h>

#include <string>
#include <list>
#include <map>
#include <algorithm>

#include "common.h"

#define LOGD if(m_debugOutput) wcout

using std::list;
using std::pair;
using std::map;
using std::wstring;
using std::to_wstring;
using std::wcout;
using std::endl;

const list<EventType> WindowsEventParser::SYSTEM_EVENTS_START = {
//    Event(EventID::SLEEP_OFF, L"Microsoft-Windows-Power-Troubleshooter"),
    EventType(EventID::TURN_ON, L"Microsoft-Windows-Kernel-General")
};

const list<EventType> WindowsEventParser::SYSTEM_EVENTS_FINISH = {
//    EventType(EventID::SLEEP_ON, L"Microsoft-Windows-Kernel-Power"),
    EventType(EventID::TURN_OFF, L"Microsoft-Windows-Kernel-General")
};

const std::list<EventType> WindowsEventParser::SECURITY_EVENTS_START = {
    EventType(EventID::SEC_UNLOCK, L"Microsoft-Windows-Security-Auditing"),
};

const std::list<EventType> WindowsEventParser::SECURITY_EVENTS_FINISH = {
    EventType(EventID::SEC_LOCK, L"Microsoft-Windows-Security-Auditing"),
};

pair<map<time_t, time_t>, map<time_t, time_t>> WindowsEventParser::getLogTimesByDate(const time_t &dateFrom, const time_t &dateTo) const
{        
    map<time_t, time_t> daysLogOns, daysLogOffs;
    int status = -1;
    wstring path = L"";
    list<EventType> events;
    if(m_flags & ParserFlag::USE_SYSTEM_EVENTS)
    {
        path = L"System";
        events.insert(events.end(), SYSTEM_EVENTS_START.begin(), SYSTEM_EVENTS_START.end());
        events.insert(events.end(), SYSTEM_EVENTS_FINISH.begin(), SYSTEM_EVENTS_FINISH.end());
        status = getEventTimesByDate(dateFrom, dateTo, &events, path, &daysLogOns, &daysLogOffs);
        if(status != ERROR_SUCCESS)
        {
            LOGD<<L"getEventTimesByDate Failed By System Events" << endl;
            LOGD << L"Error: " << status << endl;
            wcout<<L"Failed to Get Log Time for date: "<<ctime(&dateFrom);
        }
    }
    if(m_flags & ParserFlag::USE_SECURITY_EVENTS)
    {
        path = L"Security";        
        events.insert(events.end(), SECURITY_EVENTS_START.begin(), SECURITY_EVENTS_START.end());
        events.insert(events.end(), SECURITY_EVENTS_FINISH.begin(), SECURITY_EVENTS_FINISH.end());
        status = getEventTimesByDate(dateFrom, dateTo, &events, path, &daysLogOns, &daysLogOffs);
        if(status != ERROR_SUCCESS)
        {
            LOGD<<L"getEventTimesByDate Failed By Security Events" << endl;                        
            LOGD << L"Error: " << status << endl;
            wcout<<L"Failed to Get Log Time for date: "<<ctime(&dateFrom);
        }
    }        
    return {daysLogOns, daysLogOffs};
}

DWORD WindowsEventParser::getEventTimesByDate(const time_t &dateFrom, const time_t &dateTo, const std::list<EventType> *events, const std::wstring &path, map<time_t, time_t> *daysLogOns, map<time_t, time_t> *daysLogOffs) const
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

    struct tm dateTMFrom, dateTMTo;
    //TODO check for errors
    localtime_s(&dateTMFrom, &dateFrom);
//    auto dateTo = dateFrom + 3600*24; // Add day in seconds 3600 seconds in hour * 24 hours
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
        return status;
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
    sPwsQuery += L"@SystemTime < ";
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
    getResults(hResults, path, daysLogOns, daysLogOffs);
clean:
    if (hResults)
    {        
        EvtClose(hResults);
    }    
    return status;
}

DWORD WindowsEventParser::getResults(EVT_HANDLE hResults, const std::wstring &path, map<time_t, time_t> *daysLogOns, map<time_t, time_t> *daysLogOffs) const
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;
    const std::list<EventType> *eventStartList = nullptr;
    const std::list<EventType> *eventFinishList = nullptr;
    if(path == L"System")
    {
        eventStartList = &SYSTEM_EVENTS_START;
        eventFinishList = &SYSTEM_EVENTS_FINISH;
    }
    else if(path == L"Security")
    {
        eventStartList = &SECURITY_EVENTS_START;
        eventFinishList = &SECURITY_EVENTS_FINISH;
    }

    if(!eventStartList || !eventFinishList)
    {
        wcout << L"No event Start List of Finish List" << endl;
        return ERROR_NO_EVENTS;
    }

    auto checkIfLogin = [&](const auto &eventType) {
        if(std::count(eventStartList->begin(), eventStartList->end(), eventType))
            return true;
        else
            return false;
    };


    map<time_t, time_t> *daysLog;
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



        for (DWORD i = 0; i < dwReturned; i++)
        {
            EventInfo eventInfo;
            if (ERROR_SUCCESS == (status = getEventInfo(hEvents[i], &eventInfo)))
            {
                bool isLogin = checkIfLogin(eventInfo.type);
                daysLog = isLogin?daysLogOns:daysLogOffs;

                struct tm date;
                localtime_s(&date, &eventInfo.time);
                date.tm_hour = 0;
                date.tm_min = 0;
                date.tm_sec = 0;

                time_t day = mktime(&date);
                wcout<<L"GOOD getResults for Event:" << static_cast<int>(eventInfo.type.id) << " " << ctime(&day) << " isLogin " << isLogin << endl;
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;

                auto dayIt = daysLog->find(day);
                bool shouldWrite = false;
                if(dayIt != daysLog->end())
                {
                    wcout<<L"Already found that day with time "<<ctime(&dayIt->second);
                    wcout<<L"New time is "<<ctime(&eventInfo.time);
                    if(isLogin && dayIt->second > eventInfo.time || !isLogin && dayIt->second < eventInfo.time)
                    {
                        wcout<<L"Overwrite";
                        shouldWrite = true;
                    }
                }
                else
                {
                    wcout<<L"Not found that day "<<ctime(&eventInfo.time)<<endl;
                    shouldWrite = true;
                }

                if(shouldWrite)
                    (*daysLog)[day] = eventInfo.time;
            }
            else
            {
                wcout<<"Error getResults"<<endl;
                goto cleanup;
            }
        }
    }

cleanup:   
    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}

DWORD WindowsEventParser::getEventInfo(EVT_HANDLE hEvent, EventInfo *eventInfo) const
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
    EventType type;

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

    DWORD eventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type)
    {
        eventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
    }

    type.id = static_cast<EventID>(eventID);
    type.source = pRenderedValues[EvtSystemProviderName].StringVal;

    ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    //wprintf(L"ullTimeStamp: %I64u\n", ullTimeStamp);
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    //wprintf(L"high: %I64u\n", ft.dwHighDateTime);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

    FileTimeToLocalFileTime(&ft, &lt);
    FileTimeToSystemTime(&lt, &st);



    eventInfo->time = getTimeFromSystemTime(st);
    eventInfo->type = type;

cleanup:

    if (hContext)
        EvtClose(hContext);

    if (pRenderedValues)
        free(pRenderedValues);

    return status;
}



bool operator ==(const EventType &first, const EventType &second)
{
    return first.id == second.id && first.source == second.source;
}
