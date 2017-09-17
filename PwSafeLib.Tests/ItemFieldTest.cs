using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafeLib.Crypto;
using PwSafeLib.Filesystem;

namespace PwSafeLib.Tests
{
    [TestClass]
    public class ItemFieldTest
    {
        static readonly byte[] SessionKey = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
           // 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        };

        private SecureString CreatePasskey(string password = null)
        {
            SecureString spw;
            unsafe
            {
                var s = password ?? "test";
                char* pw = (char*)Marshal.StringToHGlobalUni(s);
                spw = new SecureString(pw, s.Length);
            }
            return spw;
        }

        private BlowFish _bf;

        public ItemFieldTest()
        {
            _bf = new BlowFish(SessionKey);
        }

        [TestMethod]
        public void ItemField_Get_StoringUuid_ReturnsSetData()
        {
            var data = new byte[] {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};

            var field = new ItemField(Item.FieldType.Uuid);
            Assert.IsTrue(field.IsEmpty);
            Assert.AreEqual(Item.FieldType.Uuid, field.Type);

            field.Set(data, Item.FieldType.End, _bf);
            var data2 = field.Get(_bf);

            CollectionAssert.AreEqual(data, data2);
        }

        [TestMethod]
        public void ItemData_SecurePassword_StoresCorrectPassword()
        {
            var d =new ItemData();
            var sr = CreatePasskey("testÜ");
            d.SecurePassword = sr;

            Assert.AreEqual("testÜ", d.Password);

            var p = Marshal.SecureStringToGlobalAllocUnicode(d.SecurePassword);
            unsafe
            {
                var ps = new string((char*) p.ToPointer());
                Assert.AreEqual("testÜ", ps);
            }
            Marshal.ZeroFreeGlobalAllocUnicode(p);
            
        }
    }
}
