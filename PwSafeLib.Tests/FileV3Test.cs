using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PwSafeLib.Filesystem;
using PwSafeLib.Passwords;

namespace PwSafeLib.Tests
{
    [TestClass]
    public class FileV3Test
    {
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

        private ItemData CreateSmallItem()
        {
            var smallItem = new ItemData();
            smallItem.CreateUuid();
            smallItem.SetTitle("picollo");
            smallItem.Password = "tiny-passw";
            return smallItem;
        }

        private ItemData CreateFullItem()
        {
            var fullItem = new ItemData();
            fullItem.CreateUuid();
            fullItem.SetTitle("a-title");
            fullItem.Password = "b-password!?";
            fullItem.User = "C-UserR-ינור";
            fullItem.Notes = "N is for notes\nwhich can span lines\r\nin several ways.";
            fullItem.Group = "Groups.are.nested.by.dots";
            fullItem.Url = "http://pwsafe.org/";
            fullItem.AutoType = "\\u\\t\\t\\n\\p\\t\\n";
            fullItem.Email = "joe@spammenot.com";
            fullItem.PolicyName = "liberal";
            fullItem.Symbols = "<-_+=@?>";
            fullItem.RunCommand = "Run 4 your life";
            fullItem.LastAccessTime = new DateTime(2014, 9, 5, 9, 14, 52);
            fullItem.CreationTime = new DateTime(2014, 9, 5, 9, 14, 53);
            fullItem.PasswordExpiryTime = new DateTime(2014, 9, 5, 9, 14, 54);
            fullItem.LastPasswordChangeTime = new DateTime(2014, 9, 5, 9, 14, 55);
            fullItem.LastOtherValueChangeTime = new DateTime(2014, 9, 5, 9, 14, 56);
            fullItem.Dca = 3;
            fullItem.ShiftDca = 8;
            fullItem.KbShortcut = 0x12345678;
            return fullItem;
        }

        [TestMethod, ExpectedException(typeof(UnauthorizedAccessException))]
        public async Task PwsFileV3_Open_WrongPassword_ThrowsException()
        {
            var ms = new MemoryStream();
            var pws = new PwsFileV3(ms, CreatePasskey(), FileMode.Create);
            await pws.OpenAsync();
            pws.Dispose();

            ms.Position = 0;
            await PwsFile.OpenAsync(ms, CreatePasskey("x"));
        }


        [TestMethod]
        public async Task PwsFileV3_Open_FileCreated_OvertakesHeaderData()
        {
            var ms = new MemoryStream();
            var pws = new PwsFileV3(ms, CreatePasskey(), FileMode.Create);

            var hdr1 = new PwsFileHeader
            {
                PrefString = "aPrefString",
                WhenLastSaved = new DateTime(2005, 2, 20, 1, 2, 3), // overwritten
                LastSavedBy = "aUser",
                LastSavedOn = "aMachine",
                WhatLastSaved = "PasswordSafe test framework",
                DbName = "aName",
                DbDescription = "Test the header's persistency"
            };
            pws.Header = hdr1;
            // write to ms
            await pws.OpenAsync();
            pws.Dispose();

            ms.Position = 0;

            var read = (PwsFileV3) await PwsFile.OpenAsync(ms, CreatePasskey());
            
            Assert.AreEqual(hdr1.PrefString, read.Header.PrefString);
            Assert.AreNotEqual(hdr1.WhenLastSaved, read.Header.WhenLastSaved);
            Assert.AreEqual(hdr1.LastSavedBy, read.Header.LastSavedBy);
            Assert.AreEqual(hdr1.LastSavedOn, read.Header.LastSavedOn);
            Assert.AreEqual(hdr1.WhatLastSaved, read.Header.WhatLastSaved);
            Assert.AreEqual(hdr1.DbName, read.Header.DbName);
            Assert.AreEqual(hdr1.DbDescription, read.Header.DbDescription);

            while (await read.ReadRecordAsync() != null)
            {
                // read till end, so Dispose won't throw (end record is included in hmac)
            }

            read.Dispose();
        }

      

        [TestMethod]
        public async Task PwsFileV3_ItemData_SaveItem_StoresItemsCorrectly()
        {
            var smallItem = CreateSmallItem();
            var fullItem = CreateFullItem();
            

            var ms = new MemoryStream();
            var pws = new PwsFileV3(ms, CreatePasskey(), FileMode.Create);
            await pws.OpenAsync();

            
            await pws.WriteRecordAsync(smallItem);
            await pws.WriteRecordAsync(fullItem);

            pws.Dispose();

            ms.Position = 0;
            var read = (PwsFileV3) await PwsFile.OpenAsync(ms, CreatePasskey());
            var readSmallItem = await read.ReadRecordAsync();
            var readFullItem = await read.ReadRecordAsync();

            Assert.AreEqual(smallItem, readSmallItem);
            Assert.AreEqual(fullItem, readFullItem);
            //33
            File.WriteAllBytes(@"q:\Projekte_NoBackup\pwsafe\ConsoleApplication1\testcs.dat", ms.ToArray());
        }


        [TestMethod]
        public async Task PwsFileV3_ItemData_ReadFileFromNativeSafe_ReadsItemsCorrectly()
        {
            using (var ms =
                typeof(FileV3Test).Assembly.GetManifestResourceStream(typeof(FileV3Test), "Resources.test.pwsafe3"))
            {
                var read = (PwsFileV3)await PwsFile.OpenAsync(ms, CreatePasskey());
                var readSmallItem = await read.ReadRecordAsync();
                var readFullItem = await read.ReadRecordAsync();

                var smallItem = CreateSmallItem();
                var fullItem = CreateFullItem();

                Assert.AreNotEqual(Guid.Empty, readSmallItem.Uuid);
                Assert.AreNotEqual(Guid.Empty, readFullItem.Uuid);
                // uuids will always be different
                smallItem.Uuid = readSmallItem.Uuid;
                fullItem.Uuid = readFullItem.Uuid;

                Assert.AreEqual(smallItem, readSmallItem);
                Assert.AreEqual(fullItem, readFullItem);

                while (await read.ReadRecordAsync() != null)
                {
                    // read till end, so Dispose won't throw (end record is included in hmac)
                }

                read.Dispose();
            }
        }


        [TestMethod]
        public async Task PwsFileV3_ItemData_UnkownFields_ArePersisted()
        {
            var d1 = new ItemData();
            d1.CreateUuid();
            d1.Title = "future";
            d1.Password = "possible";
            var uv = new byte[] { 55, 42, 78, 30, 16, 93 };
            d1.SetUnknownField(Item.FieldType.UnknownTesting, uv);

            var ms = new MemoryStream();
            var pws = new PwsFileV3(ms, CreatePasskey(), FileMode.Create);
            await pws.OpenAsync();
            await pws.WriteRecordAsync(d1);
            pws.Dispose();

            ms.Position = 0;
            var read = (PwsFileV3) await PwsFile.OpenAsync(ms, CreatePasskey());
            var item = await read.ReadRecordAsync();

            Assert.AreEqual(d1, item);
            Assert.IsNull(await read.ReadRecordAsync());
            read.Dispose();
        }

        [TestMethod]
        public async Task PwsFileV3_PwPolicy_IsPersisted()
        {
            var ms = new MemoryStream();
            var pws = new PwsFileV3(ms, CreatePasskey(), FileMode.Create);
            pws.PasswordPolicies["Test"] = new PwPolicy
            {
                Flags = PwPolicyFlags.UseEasyVision | PwPolicyFlags.UseSymbols,
                Length = 10,
                DigitMinLength = 1,
                LowerMinLength = 2,
                SymbolMinLength = 3,
                UpperMinLength = 4,
                Symbols = "{}"
            };
            await pws.OpenAsync();
            
            pws.Dispose();

            ms.Position = 0;
            var read = (PwsFileV3)await PwsFile.OpenAsync(ms, CreatePasskey());

            Assert.AreEqual(1, read.PasswordPolicies.Count);
            var pwp = read.PasswordPolicies["Test"];
            Assert.AreEqual(PwPolicyFlags.UseEasyVision | PwPolicyFlags.UseSymbols, pwp.Flags);
            Assert.AreEqual(10, pwp.Length);
            Assert.AreEqual(1, pwp.DigitMinLength);
            Assert.AreEqual(2, pwp.LowerMinLength);
            Assert.AreEqual(3, pwp.SymbolMinLength);
            Assert.AreEqual(4, pwp.UpperMinLength);
            Assert.AreEqual("{}", pwp.Symbols);

            while (await read.ReadRecordAsync() != null)
            {
                // read till end, so Dispose won't throw (end record is included in hmac)
            }
            read.Dispose();
            
         
        }
    }
}
