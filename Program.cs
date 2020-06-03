using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using System.Security;

namespace test
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var logsWatcher = new LogsWatcher();
            Thread.Sleep(1000 * 30 * 1000);
        }
    }

    public class LogsWatcher
    {
        List<EventLog> logs { get; set; }

        public LogsWatcher()
        {
            OnStart(new string[] { });
        }

        protected /*override*/ void OnStart(string[] args)
        {
            var remoteComputer = null;
            var domain = null;
            var password = null;
            var userName = null;

            EventLogSession session = new EventLogSession(
                remoteComputer,                          // Remote Computer
                domain,                                  // Domain
                userName,                                // Username
                password,
                SessionAuthentication.Default);

            String xpath = "*[System[EventID=4624 or EventID=4634]]";

            var query = new EventLogQuery("Security", PathType.LogName, xpath);
            query.Session = session;

            var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += OnEntryWritten;
            watcher.Enabled = true;
        }

        void OnEntryWritten(object source, EventRecordWrittenEventArgs evt)
        {
            EventLogRecord e = (EventLogRecord) evt.EventRecord;

            using (var loginEventPropertySelector = new EventLogPropertySelector(new[]
            {
                // (The XPath expression evaluates to null if no Data element exists with the specified name.)
                "Event/EventData/Data[@Name='TargetUserSid']",
                "Event/EventData/Data[@Name='TargetLogonId']",
                "Event/EventData/Data[@Name='LogonType']",
                "Event/EventData/Data[@Name='ElevatedToken']",
                "Event/EventData/Data[@Name='WorkstationName']",
                "Event/EventData/Data[@Name='ProcessName']",
                "Event/EventData/Data[@Name='IpAddress']",
                "Event/EventData/Data[@Name='IpPort']",
                "Event/EventData/Data[@Name='TargetUserName']"
            }))

            using (var logoffEventPropertySelector = new EventLogPropertySelector(new[]
            {
                "Event/EventData/Data[@Name='TargetUserSid']",
                "Event/EventData/Data[@Name='TargetLogonId']"
            }))

            switch (e.Id)
            {
                case 4624:
                    var loginPropertyValues = ((EventLogRecord)e).GetPropertyValues(loginEventPropertySelector);
                    var sid = loginPropertyValues[0];
                    var logonId = loginPropertyValues[1];
                    var logonType = loginPropertyValues[2];
                    var elevatedToken = loginPropertyValues[3];
                    var workstationName = loginPropertyValues[4];
                    var processName = loginPropertyValues[5];
                    var ipAddress = loginPropertyValues[6];
                    var ipPort = loginPropertyValues[7];
                    var userName = loginPropertyValues[8];

                    Console.WriteLine("got eventId={0} sid={1} logonId={2} logonType={3} token={4} workstation={5} process={6} ip={7} port={8} user={9}",
                        e.Id, sid, logonId, logonType, elevatedToken, workstationName, processName, ipAddress, ipPort, userName);
               
                    break;

                case 4634:
                    var logoffPropertyValues = ((EventLogRecord)e).GetPropertyValues(logoffEventPropertySelector);
                    var sid1 = logoffPropertyValues[0];
                    var logoffId = logoffPropertyValues[1];

                    Console.WriteLine("got eventId={0} sid={1} logonId={2}",
                        e.Id, sid1, logoffId);
                    
                    break;
            }

        }


        SecureString ToSecureString(string plainString)
        {
            SecureString secureString = new SecureString();
            foreach (char c in plainString.ToCharArray())
            {
                secureString.AppendChar(c);
            }
            return secureString;
        }
    }
}
