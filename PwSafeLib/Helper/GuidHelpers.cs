using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PwSafeLib.Helper
{
    static class GuidHelpers
    {
        public static byte[] ToArray(this Guid guid)
        {
            var data = guid.ToByteArray();
             
            var data1 = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, 0));
            var data2 = IPAddress.HostToNetworkOrder(BitConverter.ToInt16(data, 4));
            var data3 = IPAddress.HostToNetworkOrder(BitConverter.ToInt16(data, 6));
            var data4 = new byte[8];
            Array.Copy(data, 8, data4, 0, 8);
            return new Guid(data1, data2, data3, data4).ToByteArray();
        }

        public static Guid ToGuid(this byte[] data)
        {
            if (data.Length != 16)
            {
                throw new NotSupportedException("Invalid UUID");
            }
            var data1 = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, 0));
            var data2 = IPAddress.HostToNetworkOrder(BitConverter.ToInt16(data, 4));
            var data3 = IPAddress.HostToNetworkOrder(BitConverter.ToInt16(data, 6));
            var data4 = new byte[8];
            Array.Copy(data, 8, data4, 0, 8);

            return new Guid(data1, data2, data3, data4);
        }
    }
}
