using System;
using System.Text;
using PwSafeLib.Crypto;
using PwSafeLib.Helper;

namespace PwSafeLib.Filesystem
{
    public class ItemField
    {
        private Item.FieldType _type;
        private int _length;
        private byte[] _data;

        public ItemField(Item.FieldType type)
        {
            _type = type;
        }

        public bool IsEmpty => _length == 0;
        public Item.FieldType Type => _type;
        public int Length => _length;


        internal void Set(byte[] value, Item.FieldType type, BlowFish bf)
        {
            _length = value.Length;
            if (_length == 0)
            {
                _data = null;
            }
            else
            {
                _data = bf.Encrypt_ECB(value);
            }
            if (type != Item.FieldType.End)
            {
                _type = type;
            }
        }

        internal void Set(string value, Item.FieldType type, BlowFish bf)
        {
            Set(Encoding.UTF8.GetBytes(value), type, bf);
        }

        internal byte[] Get(BlowFish bf)
        {
            if (_length == 0)
            {
                return new byte[0];
            }
            // we have data to decrypt
            var result = new byte[_length];
            var decrypted = bf.Decrypt_ECB(_data);
            Array.Copy(decrypted, result, _length);
            PwsUtil.TrashMemory(decrypted);
            return result;
        }

        internal string GetString(BlowFish bf)
        {
            return Encoding.UTF8.GetString(Get(bf));
        }
    }
}