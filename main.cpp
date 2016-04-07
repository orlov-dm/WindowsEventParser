//#include <QCoreApplication>
#include "windowseventparser.h"

#include "common.h"
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <winevt.h>
#include <iostream>
#include <Objbase.h>
#include <string>
#include <ctime>
#include <list>
using namespace std;
//#pragma comment(lib, "wevtapi.lib")
//#pragma comment(lib, "Ole32.lib")
//#pragma comment(lib, "Advapi32.lib")

#include <QDateTime>


int main()
{	
    bool needDebug = false;
#ifdef DEBUG_OUTPUT
    needDebug = true;
#endif
	// Just a test use case
    cout << "Enter 1 for USE_SYSTEM_EVENTS or 2 for USE_SECURITY_EVENTS:" << endl;
    ParserFlag flag;
    int getFlag;
    cin >> getFlag;
    if(getFlag)
        flag = static_cast<ParserFlag>(getFlag);
    if(getFlag == ParserFlag::USE_SYSTEM_EVENTS || getFlag == ParserFlag::USE_SECURITY_EVENTS)
    {
        WindowsEventParser testParser(flag, needDebug);
        QDateTime dt;
        for(int i = 1; i <= 31; ++i)
        {
            dt.setDate(QDate(2016,3,i));
            auto now1 = dt.toTime_t();
            auto logOn = testParser.getLogOnTimeByDate(now1);
            auto logOff = testParser.getLogOffTimeByDate(now1);
            if(logOn)
                cout<<"Log On  : " << ctime(&logOn);
            if(logOff)
                cout<<"Log Off : " << ctime(&logOff);
            //break;
        }
        for(int i = 1; i <= 7; ++i)
        {
            dt.setDate(QDate(2016,4,i));
            auto now1 = dt.toTime_t();
            auto logOn = testParser.getLogOnTimeByDate(now1);
            auto logOff = testParser.getLogOffTimeByDate(now1);
            if(logOn)
                cout<<"Log On  : " << ctime(&logOn);
            if(logOff)
                cout<<"Log Off : " << ctime(&logOff);
            //break;
        }
    }
    else
    {
        cout << "Wrong Flag" << endl;
    }
        
    int a = 0;
    cin >> a;
    return 0;
}
