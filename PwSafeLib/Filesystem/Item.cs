using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using PwSafeLib.Crypto;
using PwSafeLib.Helper;

namespace PwSafeLib.Filesystem
{
    public class Item 
    {
        protected readonly Dictionary<FieldType, ItemField> _fields = new Dictionary<FieldType, ItemField>();
        protected readonly List<ItemField> _unkownItemFields = new List<ItemField>();
        internal BlowFish _fish;
        private readonly byte[] _key = new byte[32];

        protected bool IsItemDataField(FieldType type)
        {
            return type >= FieldType.Start && type < FieldType.LastData;
        }

        protected bool IsItemAttField(FieldType type)
        {
            return type >= FieldType.StartAtt && type < FieldType.LastAtt;
        }

        protected void SetUnkownField(PwsRecord field)
        {
            var f = new ItemField((FieldType) field.Type);
            f.Set(field.Buffer, (FieldType)field.Type, MakeBlowFish());
            _unkownItemFields.Add(f);
        }

        internal BlowFish MakeBlowFish()
        {
            if (_fish == null)
            {
                _fish = new BlowFish(_key);
            }
            return _fish;
        }

        protected void SetField(FieldType type, byte[] data)
        {
            if (data != null && data.Length > 0)
            {
                if (!_fields.ContainsKey(type))
                {
                    _fields[type] = new ItemField(type);
                }
                _fields[type].Set(data, type, MakeBlowFish());
            }
            else
            {
                _fields.Remove(type);
            }
        }

        protected void SetField(FieldType type, int value)
        {
            SetField(type, BitConverter.GetBytes(value));
        }

        protected void SetField(FieldType type, short value)
        {
            SetField(type, BitConverter.GetBytes(value));
        }

        protected void SetField(FieldType type, byte value)
        {
            SetField(type, new[]{value});
        }


        protected void SetTime(FieldType whichtime, long value)
        {
            SetField(whichtime, BitConverter.GetBytes(value));
        }

        protected void SetField(FieldType type, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                if (!_fields.ContainsKey(type))
                {
                    _fields[type] = new ItemField(type);
                }
                _fields[type].Set(value, type, MakeBlowFish());
            }
            else
            {
                _fields.Remove(type);
            }
        }



        protected bool SetTimeField(byte[] data, FieldType type)
        {
            if (PwsUtil.TryPullTime(data, out var time))
            {
                SetTime(type, time);
                return true;
            }
            return false;
        }

        public void ClearField(FieldType ft)
        {
            _fields.Remove(ft);
        }

        public void Clear()
        {
            _fields.Clear();
            _unkownItemFields.Clear();
        }

        public enum FieldType
        {
            Start = 0x00,
            Grouptitle = 0x00 /* reusing depreciated NAME for Group.Title combination */,
            Name = 0x00,
            Uuid = 0x01,
            Group = 0x02,
            Title = 0x03,
            User = 0x04,
            Notes = 0x05,
            Password = 0x06,
            Ctime = 0x07, // Entry 'C'reation time
            Pmtime = 0x08, // last 'P'assword 'M'odification time
            Atime = 0x09, // last 'A'ccess time
            Xtime = 0x0a, // password e'X'piry time
            Reserved = 0x0b /* MUST NOT USE */,
            Rmtime = 0x0c, // last 'R'ecord 'M'odification time
            Url = 0x0d,
            Autotype = 0x0e,
            Pwhist = 0x0f,
            Policy = 0x10, // string encoding of item-specific password policy
            XtimeInt = 0x11,
            Runcmd = 0x12,
            Dca = 0x13, // doubleclick action (enum)
            Email = 0x14,
            Protected = 0x15,
            Symbols = 0x16, // string of item-specific password symbols
            Shiftdca = 0x17, // shift-doubleclick action (enum)
            Policyname = 0x18, // named non-default password policy for item
            Kbshortcut = 0x19, // Keyboard shortcuts
            Attref = 0x1a, // UUID of attachment (v4)
            LastUserField, // All "user" fields MUST be before this for entry compare

            Baseuuid = 0x41, // Base UUID of Alias or Shortcut (v4)
            Aliasuuid = 0x42, // UUID indicates this is an Alias (v4)
            Shortcutuuid = 0x43, // UUID indicates this is a Shortcut (v4)
            LastData, // Start of unknown fields!
            LastItemDataField = 0x5f, // beyond this is for other CItem subclasses

            StartAtt = 0x60,
            Attuuid = 0x60,
            Atttitle = 0x61,
            Attctime = 0x62,
            Mediatype = 0x63,
            Filename = 0x64,
            Filepath = 0x65,
            Filectime = 0x66,
            Filemtime = 0x67,
            Fileatime = 0x68,
            LastSearchable = 0x6f, // also last-filterable
            Attek = 0x70,
            Attak = 0x71,
            Attiv = 0x72,
            Content = 0x73,
            Contenthmac = 0x74,
            LastAtt,

            UnknownTesting = 0xdf, // for testing forward compatability (unknown field handling)
            End = 0xff,

            // Internal fields only - used in filters
            Entrysize = 0x100,
            Entrytype = 0x101,
            Entrystatus = 0x102,
            Passwordlen = 0x103,

            // 'UNKNOWNFIELDS' should be last
            Unknownfields = 0x104,
            LastField
        }

        protected byte[] GetField(ItemField field)
        {
            return field.Get(MakeBlowFish());
        }

        protected string GetFieldString(ItemField field)
        {
            return field.GetString(MakeBlowFish());
        }

        protected string GetField(FieldType ft)
        {
            if (_fields.TryGetValue(ft, out var result))
            {
                return GetFieldString(result);
            }
            return "";
        }

        protected byte[] GetFieldData(FieldType ft)
        {
            if (_fields.TryGetValue(ft, out var result))
            {
                return GetField(result);
            }
            return null;
        }

        protected int GetIntField(FieldType ft)
        {
            if (_fields.TryGetValue(ft, out var result))
            {
                return BitConverter.ToInt32(GetField(result), 0);
            }
            return 0;
        }

        protected short GetShortField(FieldType ft)
        {
            if (_fields.TryGetValue(ft, out var result))
            {
                return BitConverter.ToInt16(GetField(result), 0);
            }
            return 0;
        }

        protected byte GetByteField(FieldType ft)
        {
            if (_fields.TryGetValue(ft, out var result))
            {
                return GetField(result)[0];
            }
            return 0;
        }

        protected long GetTime(FieldType whichTime)
        {
            if (_fields.TryGetValue(whichTime, out var field))
            {
                var data = GetField(field);
                if (data.Length > 0)
                {
                    if (!PwsUtil.TryPullTime(data, out var result))
                    {
                        throw new InvalidOperationException();
                    }
                    return result;
                }
            }
            return 0;
        }

        public void SetUnknownField(FieldType ft, byte[] data)
        {
            var unkrfe = new ItemField(ft);
            unkrfe.Set(data, ft, MakeBlowFish());
            _unkownItemFields.Add(unkrfe);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Item) obj);
        }

        public override int GetHashCode()
        {
            return 0;
        }

        protected bool Equals(Item other)
        {
            if (_fields.Count == other._fields.Count &&
                _unkownItemFields.Count == other._unkownItemFields.Count)
            {
                /**
                 * It would be nice to be able to compare the m_fields
                 * and m_URFL directly, but the fields would be
                 * encrypted with different keys, making byte-wise
                 * field comparisons infeasible.
                 */
                foreach (var mf in _fields) {
                    if (other._fields.TryGetValue(mf.Key, out var otherVal))
                    {
                        if (!CompareFields(mf.Value, other, otherVal))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }

            var alist = _unkownItemFields.OrderBy(s => s.Type).ToArray();
            var blist = other._unkownItemFields.OrderBy(s => s.Type).ToArray();
            for (int i = 0; i < alist.Length; i++)
            {
                if (!CompareFields(alist[i], other, blist[i]))
                {
                    return false;
                }
            }
            return true;
        }


        bool CompareFields(ItemField x, Item that, ItemField y)
        {
            if (x.Length != y.Length)
            {
                Debug.WriteLine($"Field lengths mismatched ('{x.Type}, {x.Length}', '{y.Type}, {y.Length}')");
                return false;
            }
            if (x.Type != y.Type)
            {
                Debug.WriteLine($"Field types mismatched ('{x.Type}', '{y.Type}')");
                return false;
            }
            var a = GetField(x);
            var b = that.GetField(y);
            var result = a.SequenceEqual(b);
#if DEBUG
            if (!result)
            {
                Debug.WriteLine($"Fields {x.Type} mismatched ('{string.Join(",", a)}', '{string.Join(", ", b)}')");
            }
#endif
            PwsUtil.TrashMemory(a);
            PwsUtil.TrashMemory(b);
            return result;
        }
        
    }
}