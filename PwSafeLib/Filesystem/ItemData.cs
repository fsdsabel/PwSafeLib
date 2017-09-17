using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using PwSafeLib.Helper;

namespace PwSafeLib.Filesystem
{
    public class ItemData : Item
    {
        private EntryType _entryType;

        /// <summary>
        /// The password the user set for an entry as a <see cref="SecureString"/>. If security is not a primary
        /// consideration in your implementation, you may use <see cref="Password"/> for easier access. This is not recommended though!
        /// </summary>
        public SecureString SecurePassword
        {
            get
            {
                // most of this is conversion between UTF-8 and Unicode UTF-16 in a save way (no usage of string)

                var pwdata = GetFieldData(FieldType.Password);
                if (pwdata == null)
                {
                    return null;
                }
                SecureString result;
                unsafe
                {
                    
                    var charcount = Encoding.UTF8.GetDecoder().GetCharCount(pwdata, 0, pwdata.Length);
                    var chars = new char[charcount];
                    Encoding.UTF8.GetDecoder().GetChars(pwdata, 0, pwdata.Length, chars, 0, true);

                    var ppwdata = Marshal.AllocHGlobal(chars.Length*2);
                    Marshal.Copy(chars, 0, ppwdata, chars.Length);

                    result = new SecureString((char*)ppwdata, chars.Length);
                    Marshal.ZeroFreeGlobalAllocUnicode(ppwdata);
                    PwsUtil.TrashMemory(pwdata);
                    PwsUtil.TrashMemory(chars);
                }
                return result;
            }
            set
            {
                if (value == null)
                {
                    SetField(FieldType.Password, null);
                }
                else
                {
                    var ppwdata = Marshal.SecureStringToGlobalAllocUnicode(value);
                    var pwdata = new byte[value.Length * 2];
                    Marshal.Copy(ppwdata, pwdata, 0, value.Length * 2);
                    var chars = new char[value.Length];
                    Encoding.Unicode.GetDecoder().Convert(pwdata, 0, value.Length*2, chars, 0, chars.Length, true, out var _, out var _, out var _);
                    SetField(FieldType.Password, Encoding.UTF8.GetBytes(chars));
                    PwsUtil.TrashMemory(pwdata);
                    PwsUtil.TrashMemory(chars);
                    Marshal.ZeroFreeGlobalAllocUnicode(ppwdata);
                }
            }
        }

        /// <summary>
        /// The password the user saved for the entry. Be careful though, .NET strings are not save for cryptography!
        /// <see cref="SecurePassword"/> for a better alternative.
        /// </summary>
        public string Password
        {
            get => GetField(FieldType.Password);
            set => SetField(FieldType.Password, value);
        }

        public bool IsDependent => IsAlias || IsShortcut;
        public bool IsShortcut => _entryType == EntryType.EtShortcut;

        public bool IsBase => IsAliasBase || IsShortcutBase;
        public bool IsShortcutBase => _entryType == EntryType.EtShortcutbase;

        public bool IsAliasBase => _entryType == EntryType.EtAliasbase;

        public bool IsAlias => _entryType == EntryType.EtAlias;


        public bool HasUuid => (_entryType == EntryType.EtNormal ||
                                _entryType == EntryType.EtAliasbase ||
                                _entryType == EntryType.EtShortcutbase) && IsFieldSet(FieldType.Uuid) ||
                               _entryType == EntryType.EtAlias && IsFieldSet(FieldType.Aliasuuid) ||
                               _entryType == EntryType.EtShortcut && IsFieldSet(FieldType.Shortcutuuid);

        /// <summary>
        ///     Username for the entry.
        /// </summary>
        public string User
        {
            get => GetField(FieldType.User);
            set => SetField(FieldType.User, value);
        }

        /// <summary>
        ///     Notes the user can make to the entry. This might be a multiline comment (lines seperated by \n or \r\n).
        /// </summary>
        public string Notes
        {
            get => GetField(FieldType.Notes);
            set => SetField(FieldType.Notes, value);
        }

        /// <summary>
        ///     The group the entry belongs to. Hierarchies are saved with '.'. I.e.
        ///     Main.SubGroup.Subfolder would mean: Main->SubGroup->Subfolder.
        /// </summary>
        public string Group
        {
            get => GetField(FieldType.Group);
            set => SetField(FieldType.Group, value);
        }

        /// <summary>
        ///     Saved url of the entry.
        /// </summary>
        public string Url
        {
            get => GetField(FieldType.Url);
            set => SetField(FieldType.Url, value);
        }

        public string AutoType
        {
            get => GetField(FieldType.Autotype);
            set => SetField(FieldType.Autotype, value);
        }

        /// <summary>
        ///     EMail address that the user saved for the entry.
        /// </summary>
        public string Email
        {
            get => GetField(FieldType.Email);
            set => SetField(FieldType.Email, value);
        }

        /// <summary>
        ///     Used password policy.
        /// </summary>
        public string PolicyName
        {
            get => GetField(FieldType.Policyname);
            set => SetField(FieldType.Policyname, value);
        }

        /// <summary>
        ///     Allowed symbols for password creation.
        /// </summary>
        public string Symbols
        {
            get => GetField(FieldType.Symbols);
            set => SetField(FieldType.Symbols, value);
        }

        public string RunCommand
        {
            get => GetField(FieldType.Runcmd);
            set => SetField(FieldType.Runcmd, value);
        }

        public DateTime LastAccessTime
        {
            get => ToDateTime(GetTime(FieldType.Atime));
            set => SetTime(FieldType.Atime, FromDateTime(value));
        }

        public DateTime CreationTime
        {
            get => ToDateTime(GetTime(FieldType.Ctime));
            set => SetTime(FieldType.Ctime, FromDateTime(value));
        }

        public DateTime PasswordExpiryTime
        {
            get => ToDateTime(GetTime(FieldType.Xtime));
            set => SetTime(FieldType.Xtime, FromDateTime(value));
        }

        public DateTime LastPasswordChangeTime
        {
            get => ToDateTime(GetTime(FieldType.Pmtime));
            set => SetTime(FieldType.Pmtime, FromDateTime(value));
        }

        public DateTime LastOtherValueChangeTime
        {
            get => ToDateTime(GetTime(FieldType.Rmtime));
            set => SetTime(FieldType.Rmtime, FromDateTime(value));
        }

        public short Dca
        {
            get
            {
                if (!_fields.ContainsKey(FieldType.Dca))
                    return -1;
                return GetShortField(FieldType.Dca);
            }
            set => SetField(FieldType.Dca, value);
        }

        public short ShiftDca
        {
            get
            {
                if (!_fields.ContainsKey(FieldType.Shiftdca))
                    return -1;
                return GetShortField(FieldType.Shiftdca);
            }
            set => SetField(FieldType.Shiftdca, value);
        }

        /// <summary>
        ///     Title of the entry.
        /// </summary>
        public string Title
        {
            get => GetField(FieldType.Title);
            set => SetTitle(value);
        }

        public int KbShortcut
        {
            get => GetIntField(FieldType.Kbshortcut);
            set => SetField(FieldType.Kbshortcut, value);
        }

        public int XTimeInt
        {
            get => GetIntField(FieldType.XtimeInt);
            set => SetField(FieldType.XtimeInt, value);
        }

        /// <summary>
        ///     True, if the user marked the entry as "protected". Applications should not overwrite data in this state.
        /// </summary>
        public bool Protected
        {
            get => GetByteField(FieldType.Protected) != 0;
            set
            {
                if (value)
                    SetField(FieldType.Protected, (byte) 1);
                else
                    _fields.Remove(FieldType.Protected);
            }
        }

        public Guid Uuid
        {
            get => GetGuid();
            set => SetGuid(value, FieldType.Uuid);
        }

        public Guid BaseUuid
        {
            get => GetGuid(FieldType.Baseuuid);
            set => SetGuid(value, FieldType.Baseuuid);
        }

        public Guid AttUuid
        {
            get => GetGuid(FieldType.Attuuid);
            set => SetGuid(value, FieldType.Attuuid);
        }

        internal async Task<bool> ReadAsync(PwsFile file)
        {
            FieldType type;
            var emergencyExit = 255; // to avoid endless loop.
            var numRead = 0;
            PwsRecord field;
            Clear();
            do
            {
                field = await file.ReadFieldAsync();
                if (field != null)
                {
                    type = (FieldType) field.Type;

                    if (field.ReadBytes > 0)
                    {
                        numRead += field.ReadBytes;
                        if (IsItemDataField(type))
                        {
                            SetField(type, field.Buffer);
                        }
                        else if (IsItemAttField(type))
                        {
                            // Allow rewind and retry
                            if (field.Buffer != null)
                                PwsUtil.TrashMemory(field.Buffer);
                            return false;
                        }
                        else if (type != FieldType.End)
                        {
                            SetUnkownField(field);
                        }
                    }
                    if (field.Buffer != null)
                        PwsUtil.TrashMemory(field.Buffer);
                }
                else
                {
                    type = FieldType.End;
                }
            } while (type != FieldType.End && field?.ReadBytes > 0 && --emergencyExit > 0);

            if (numRead > 0)
            {
                // Determine entry type:
                // ET_NORMAL (which may later change to ET_ALIASBASE or ET_SHORTCUTBASE)
                // ET_ALIAS or ET_SHORTCUT
                // For V4, this is simple, as we have different UUID types
                // For V3, we need to parse the password
                ParseSpecialPasswords();
                if (_fields.ContainsKey(FieldType.Uuid))
                    _entryType = EntryType.EtNormal;
                else if (_fields.ContainsKey(FieldType.Aliasuuid))
                    _entryType = EntryType.EtAlias;
                else if (_fields.ContainsKey(FieldType.Shortcutuuid))
                    _entryType = EntryType.EtShortcut;
                else
                    throw new InvalidDataException();
                return true;
            }

            return false;
        }

        private void ParseSpecialPasswords()
        {
            // For V3 records, the Base UUID and dependent type (shortcut or alias)
            // is encoded in the password field. 
            // If the password isn't in the encoded format, this is a no-op
            // If it is, then this 'normalizes' the entry record to be the same
            // as a V4 one.
            var csMyPassword = GetPassword();
            if (csMyPassword.Length == 36) // look for "[[uuid]]" or "[~uuid~]"
            {
                var csPossibleUuid = csMyPassword.Substring(2, 32); // try to extract uuid
                csPossibleUuid = csPossibleUuid.ToLower();

                if ((csMyPassword.Substring(0, 2) == "[[" &&
                     csMyPassword.Substring(csMyPassword.Length - 2) == "]]" ||
                     csMyPassword.Substring(0, 2) == "[~" &&
                     csMyPassword.Substring(csMyPassword.Length - 2) == "~]") &&
                    csPossibleUuid.All(c => "0123456789abcdef".Contains(c)))
                {
                    var buuid = Guid.Parse(csPossibleUuid);
                    SetGuid(buuid, FieldType.Baseuuid);

                    var uuid = GetGuid();
                    var ft = FieldType.Uuid;
                    if (csMyPassword.Substring(0, 2) == "[[")
                        ft = FieldType.Aliasuuid;
                    else if (csMyPassword.Substring(0, 2) == "[~")
                        ft = FieldType.Shortcutuuid;
                    else
                        throw new InvalidOperationException();
                    ClearField(FieldType.Uuid);
                    SetGuid(uuid, ft);
                }
            }
        }

        private string GetPassword()
        {
            return GetField(FieldType.Password);
        }

        private new void SetField(FieldType type, byte[] data)
        {
            switch (type)
            {
                case FieldType.Name:
                    // not serialized, or in v3 format
                    return;
                case FieldType.Uuid:
                case FieldType.Baseuuid:
                case FieldType.Aliasuuid:
                case FieldType.Shortcutuuid:
                case FieldType.Attref:
                    SetGuid(data.ToGuid(), type);
                    break;
                case FieldType.Group:
                case FieldType.Title:
                case FieldType.User:
                case FieldType.Notes:
                case FieldType.Password:
                case FieldType.Policy:
                case FieldType.Url:
                case FieldType.Autotype:
                case FieldType.Pwhist:
                case FieldType.Runcmd:
                case FieldType.Email:
                case FieldType.Symbols:
                case FieldType.Policyname:
                    SetTextField(data, type);
                    break;
                case FieldType.Ctime:
                case FieldType.Pmtime:
                case FieldType.Atime:
                case FieldType.Xtime:
                case FieldType.Rmtime:
                    SetTimeField(data, type);
                    break;
                case FieldType.XtimeInt:
                    XTimeInt = BitConverter.ToInt32(data, 0);
                    break;
                case FieldType.Dca:
                    Dca = BitConverter.ToInt16(data, 0);
                    break;
                case FieldType.Shiftdca:
                    ShiftDca = BitConverter.ToInt16(data, 0);
                    break;
                case FieldType.Protected:
                    Protected = data[0] != 0;
                    break;
                case FieldType.Kbshortcut:
                    KbShortcut = BitConverter.ToInt32(data, 0);
                    break;
                case FieldType.End:
                    break;
                default:
                    // unkowns!
                    SetUnkownField(new PwsRecord {Buffer = data, Type = (byte) type});
                    break;
            }
        }


        private void SetTextField(byte[] data, FieldType type)
        {
            if (data == null)
            {
                ClearField(type);
            }
            else
            {
                var s = Encoding.UTF8.GetString(data); // assure it's a valid string
                SetField(type, s);
            }
        }

        private void SetGuid(Guid guid, FieldType type)
        {
            base.SetField(type, guid.ToArray());
        }

        private Guid GetGuid(FieldType ft = FieldType.End)
        {
            ItemField field;
            bool found;
            if (ft != FieldType.End)
                found = _fields.TryGetValue(ft, out field);
            else
                switch (_entryType)
                {
                    case EntryType.EtNormal:
                    case EntryType.EtAliasbase:
                    case EntryType.EtShortcutbase:
                        found = _fields.TryGetValue(FieldType.Uuid, out field);
                        break;
                    case EntryType.EtAlias:
                        found = _fields.TryGetValue(FieldType.Aliasuuid, out field);
                        break;
                    case EntryType.EtShortcut:
                        found = _fields.TryGetValue(FieldType.Shortcutuuid, out field);
                        break;
                    default:
                        throw new InvalidOperationException();
                }
            if (!found)
                return Guid.Empty;
            return GetField(field).ToGuid();
        }


        public void CreateUuid(FieldType ft = FieldType.End)
        {
            var uuid = Guid.NewGuid();
            if (ft == FieldType.End)
                switch (_entryType)
                {
                    case EntryType.EtNormal:
                    case EntryType.EtShortcutbase:
                    case EntryType.EtAliasbase:
                        ft = FieldType.Uuid;
                        break;
                    case EntryType.EtAlias:
                        ft = FieldType.Aliasuuid;
                        break;
                    case EntryType.EtShortcut:
                        ft = FieldType.Shortcutuuid;
                        break;
                    default:
                        ft = FieldType.Uuid;
                        break;
                }
            SetGuid(uuid, ft);
        }

        public void SetTitle(string title, char delimiter = '\0')
        {
            if (delimiter == '\0')
            {
                SetField(FieldType.Title, title);
            }
            else
            {
                var newTitle = "";
                string newstringT, tmpstringT;
                int pos;

                newstringT = title;
                do
                {
                    pos = newstringT.IndexOf(delimiter);
                    if (pos != -1)
                    {
                        newTitle += newstringT.Substring(0, pos) + ".";
                        tmpstringT = newstringT.Substring(pos + 1);
                        newstringT = tmpstringT;
                    }
                } while (pos != -1);

                if (!string.IsNullOrEmpty(newstringT))
                    newTitle += newstringT;
                SetField(FieldType.Title, newTitle);
            }
        }


        public async Task WriteAsync(PwsFile file)
        {
            if (!HasUuid)
                throw new InvalidOperationException("UUID required");
            var ft = FieldType.End;
            if (!IsDependent)
                ft = FieldType.Uuid;
            else if (IsAlias)
                ft = FieldType.Aliasuuid;
            else if (IsShortcut)
                ft = FieldType.Shortcutuuid;
            else
                throw new InvalidOperationException();
            var itemUuid = GetGuid(ft);
            await file.WriteFieldAsync(FieldType.Uuid, itemUuid.ToArray());

            var savedPassword = Password;
            SetSpecialPasswords();

            await WriteCommonAsync(file);

            Password = savedPassword;
        }

        private async Task WriteCommonAsync(PwsFile file)
        {
            FieldType[] textFields =
            {
                FieldType.Group, FieldType.Title, FieldType.User,
                FieldType.Password, FieldType.Notes, FieldType.Url,
                FieldType.Autotype, FieldType.Policy, FieldType.Pwhist,
                FieldType.Runcmd, FieldType.Email, FieldType.Symbols, FieldType.Policyname
            };
            FieldType[] timeFields =
            {
                FieldType.Atime, FieldType.Ctime, FieldType.Xtime,
                FieldType.Pmtime, FieldType.Rmtime
            };
            foreach (var tf in textFields)
                await WriteIfSetAsync(tf, file, true);
            foreach (var tf in timeFields)
            {
                var t = GetTime(tf);
                if (t != 0)
                    if (file.TimeFieldLen == 4)
                    {
                        var buf = BitConverter.GetBytes((int) t);
                        await file.WriteFieldAsync(tf, buf);
                    }
                    else if (file.TimeFieldLen == 5)
                    {
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotSupportedException();
                    }
            }


            var i32 = XTimeInt;
            if (i32 > 0 && i32 <= 3650)
                await file.WriteFieldAsync(FieldType.XtimeInt, BitConverter.GetBytes(i32));

            i32 = KbShortcut;
            if (i32 != 0)
                await file.WriteFieldAsync(FieldType.Kbshortcut, BitConverter.GetBytes(i32));

            var i16 = Dca;
            if (i16 >= 0 && i16 <= 9)
                await file.WriteFieldAsync(FieldType.Dca, BitConverter.GetBytes(i16));

            i16 = ShiftDca;
            if (i16 >= 0 && i16 <= 9)
                await file.WriteFieldAsync(FieldType.Shiftdca, BitConverter.GetBytes(i16));

            await WriteIfSetAsync(FieldType.Protected, file, false);

            await WriteUnknownsAsync(file);
            await file.WriteFieldAsync(FieldType.End, new byte[0]);
        }

        private async Task WriteUnknownsAsync(PwsFile file)
        {
            foreach (var uif in _unkownItemFields)
            {
                var data = GetField(uif);
                await file.WriteFieldAsync(uif.Type, data);
                PwsUtil.TrashMemory(data);
            }
        }


        private async Task WriteIfSetAsync(FieldType ft, PwsFile file, bool isUtf8)
        {
            if (_fields.TryGetValue(ft, out var field))
            {
                if (field.IsEmpty)
                    throw new InvalidOperationException();
                // we store UTF8 already
                /*var flength = field.Length + 8;
                var pdata = GetField(field);
                if (isUtf8)
                {
                }
                else
                {
                    
                }*/
                var data = GetField(field);
                await file.WriteFieldAsync(ft, data);
                PwsUtil.TrashMemory(data);
            }
        }

        private void SetSpecialPasswords()
        {
            if (IsDependent)
            {
                if (!IsFieldSet(FieldType.Baseuuid))
                    throw new InvalidOperationException();
                var baseUuid = GetGuid(FieldType.Baseuuid);
                if (baseUuid == Guid.Empty)
                    throw new InvalidOperationException("Empty UUID");

                string uuidStr;
                if (IsAlias)
                    uuidStr = $"[[{baseUuid:N}]]";
                else if (IsShortcut)
                    uuidStr = $"[~{baseUuid:N}~]";
                else
                    throw new InvalidOperationException();
                Password = uuidStr;
            }
        }

        private static DateTime ToDateTime(long time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) +
                   TimeSpan.FromSeconds(time);
        }

        private static long FromDateTime(DateTime time)
        {
            return (long) (time.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        private bool IsFieldSet(FieldType ft)
        {
            return _fields.ContainsKey(ft);
        }


        private enum EntryType
        {
            EtInvalid = -1,
            EtNormal = 0,
            EtAliasbase = 1,
            EtAlias = 2,
            EtShortcutbase = 4,
            EtShortcut = 8,
            EtLast
        }
    }
}