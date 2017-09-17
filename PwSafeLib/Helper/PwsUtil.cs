using System;
using System.Collections.Generic;
using System.Text;

namespace PwSafeLib.Helper
{
    static class PwsUtil
    {
        struct Tm
        {
            public int TmSec;   // seconds after the minute - [0, 60] including leap second
            public int TmMin;   // minutes after the hour - [0, 59]
            public int TmHour;  // hours since midnight - [0, 23]
            public int TmMday;  // day of the month - [1, 31]
            public int TmMon;   // months since January - [0, 11]
            public int TmYear;  // years since 1900
            public int TmWday;  // days since Sunday - [0, 6]
            public int TmYday;  // days since January 1 - [0, 365]
            public int TmIsdst; // daylight savings time flag
        };


        public static bool TryPullTime(byte[] data, out long time)
        {
            var len = data.Length;
            time = 0;
            if (!(len == 4 || len == 5 || len == 8))
            {
                return false;
            }
            if (len == 8)
            {
                time = BitConverter.ToInt64(data, 0);
            } else if (len < 8)
            {
                var buf = new byte[8];
                Array.Copy(data, buf, len);
                time = BitConverter.ToInt64(buf, 0);
            }
            else
            {
                // convert from 40 or 64 bit time to 32 bit
                throw new NotSupportedException("Time not in supported format");
                /*var buf = new byte[8];
                Array.Copy(data, buf, len);
                var t64 = BitConverter.ToInt64(buf, 0);
                */
            }
            return true;
        }

        public static void TrashMemory<T>(T[] data)
        {
            for (var i = 0; i < data.Length; i++)
                data[i] = default(T);
        }

    }
}
