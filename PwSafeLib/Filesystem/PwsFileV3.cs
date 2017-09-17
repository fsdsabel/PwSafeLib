using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PwSafeLib.Crypto;
using PwSafeLib.Helper;

namespace PwSafeLib.Filesystem
{
    /// <inheritdoc />
    /// <summary>
    /// This exception is thrown, when a file digest does not match the saved one.
    /// This is an indicator that either the file is corrupt or it has been tampered with.
    /// </summary>
    public class BadDigestException : Exception
    {
        internal BadDigestException() : base("Digest of file is invalid.")
        {
        }
    }

    /// <summary>
    /// Implementation of v3 of a Password Safe File. It supports reading versions v3.01 up to v3.30.
    /// </summary>
    public class PwsFileV3 : PwsFile
    {
        private const int Sha256HashLen = 32;
        private const int PwSaltLength = 32;

        /**
         * Format version history:
         *
         * PasswordSafe Version   Format Version
         * =====================================
         *         V3.01           0x0300
         *         V3.03           0x0301
         *         V3.09           0x0302
         *         V3.12           0x0303
         *         V3.13           0x0304
         *         V3.14           0x0305
         *         V3.19           0x0306
         *         V3.22           0x0307
         *         V3.25           0x0308
         *         V3.26           0x0309
         *         V3.28           0x030A
         *         V3.29           0x030B
         *         V3.29Y          0x030C
         *         V3.30           0x030D
        */
        private const short VersionNum = 0x030D;

        private static readonly byte[] V3Tag = {(byte) 'P', (byte) 'W', (byte) 'S', (byte) '3'}
            ; // ASCII chars, not wchar

        private static readonly byte[] TerminalBlock =
        {
            (byte) 'P', (byte) 'W', (byte) 'S', (byte) '3', (byte) '-', (byte) 'E', (byte) 'O', (byte) 'F',
            (byte) 'P', (byte) 'W', (byte) 'S', (byte) '3', (byte) '-', (byte) 'E', (byte) 'O', (byte) 'F'
        };

        private readonly byte[] _key = new byte[32];


        private readonly SecureString _passkey;
        private HMACSHA256 _hmac;
        private uint _numHashIters;

        /// <summary>
        /// Create a new password safe instance.
        /// You can either read from a safe or write to a safe, not both.
        /// </summary>
        /// <param name="stream">Stream to read from or write to.</param>
        /// <param name="passkey">Plain text password.</param>
        /// <param name="fileMode">Decides whether to open the safe in <see cref="FileMode.Open"/> or <see cref="FileMode.Create"/> mode.</param>
        public PwsFileV3(Stream stream, SecureString passkey, FileMode fileMode = FileMode.Open)
            : base(stream, TerminalBlock, fileMode)
        {
            _passkey = passkey ?? throw new ArgumentNullException(nameof(passkey));

            if (!stream.CanRead || !stream.CanSeek)
                throw new InvalidOperationException("Need readable and seekable stream.");
        }

        /// <summary>
        /// Number of hash iterations to apply to the key.
        /// </summary>
        public uint NumHashIters
        {
            get => _numHashIters;
            set
            {
                if (value >= MinHashIterations)
                {
                    _numHashIters = value;
                }
                else if (value != 0) // default
                {
                    throw new InvalidOperationException($"Value must be at least {MinHashIterations}");
                }
            }
        }


        internal override int TimeFieldLen => 4;

        /// <inheritdoc />
        /// <summary>
        /// Open the safe for reading or writing. The actual operation depends on how the object was created.
        /// </summary>
        public override async Task OpenAsync()
        {
            switch (_fileMode)
            {
                case FileMode.Open:
                    await ReadHeaderAsync();
                    break;
                case FileMode.Create:
                    await WriteHeaderAsync();
                    break;
                default:
                    throw new ArgumentException("Filemode not supported", "fileMode");
            }
        }

        private async Task WriteHeaderAsync()
        {
            var numHashIters = NumHashIters < MinHashIterations ? MinHashIterations : NumHashIters;
            await _stream.WriteAsync(V3Tag, 0, V3Tag.Length);

            var salt = HashRandom256();
            await _stream.WriteAsync(salt, 0, salt.Length);

            var nb = BitConverter.GetBytes(numHashIters);
            await _stream.WriteAsync(nb, 0, nb.Length);

            var ptag = StretchKey(salt, numHashIters);
            using (var h = SHA256.Create())
            {
                h.Initialize();
                var hptag = h.ComputeHash(ptag);
                await _stream.WriteAsync(hptag, 0, hptag.Length);
            }

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_key);
                // ReSharper disable InconsistentNaming
                var b1b2 = new byte[_key.Length];
                var l = new byte[32]; // for HMAC
                var b3b4 = new byte[l.Length];
                // ReSharper restore InconsistentNaming
                using (var tf = new TwofishManagedTransform(ptag, CipherMode.ECB, null,
                    TwofishManagedTransformMode.Encrypt, PaddingMode.None))
                {
                    tf.TransformBlock(_key, 0, 16, b1b2, 0);
                    tf.TransformBlock(_key, 16, 16, b1b2, 16);
                    await _stream.WriteAsync(b1b2, 0, b1b2.Length);

                    rng.GetBytes(l);

                    tf.TransformBlock(l, 0, 16, b3b4, 0);
                    tf.TransformBlock(l, 16, 16, b3b4, 16);
                    await _stream.WriteAsync(b3b4, 0, b3b4.Length);

                    _hmac = new HMACSHA256(l);
                    _hmac.Initialize();
                }
            }

            var ipRand = HashRandom256();
            Array.Copy(ipRand, Ipthing, Ipthing.Length);
            await _stream.WriteAsync(Ipthing, 0, Ipthing.Length);

            Fish = new TwofishManagedTransform(_key, CipherMode.ECB, null, TwofishManagedTransformMode.Encrypt,
                PaddingMode.None);

            // Write version number
            var vnb = new byte[2];
            vnb[0] = VersionNum & 0xFF;
            vnb[1] = (VersionNum & 0xFF00) >> 8;
            Header.Version = new Version((VersionNum & 0xFF00) >> 8, VersionNum & 0xFF);

            await WriteCbcAsync(PwsFileFieldType.Version, vnb, vnb.Length);

            if (Header.Uuid == Guid.Empty)
                Header.Uuid = Guid.NewGuid();
            await WriteCbcAsync(PwsFileFieldType.Uuid, Header.Uuid.ToArray(), 16);


            await WriteUtf8CbcAsync(PwsFileFieldType.NdPrefs, Header.PrefString ?? "");

            var now = DateTime.Now;
            var pnow = BitConverter.GetBytes((int) (now.ToUniversalTime() -
                                                    new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
            await WriteCbcAsync(PwsFileFieldType.LastUpdateTime, pnow, pnow.Length);
            Header.WhenLastSaved = now;

            // Write out who saved it!
#if NETSTANDARD2_0
            Header.LastSavedBy = Environment.UserName;
            Header.LastSavedOn = Environment.MachineName;
#else
            Header.LastSavedBy = "Unknown";
            Header.LastSavedOn = Dns.GetHostName();
#endif
            await WriteUtf8CbcAsync(PwsFileFieldType.LastUpdateHost, Header.LastSavedOn);
            await WriteUtf8CbcAsync(PwsFileFieldType.LastUpdateUser, Header.LastSavedBy);

            Header.WhatLastSaved = ApplicationName;
            await WriteUtf8CbcAsync(PwsFileFieldType.LastUpdateApplication, Header.WhatLastSaved);

            if (!string.IsNullOrEmpty(Header.DbName))
                await WriteUtf8CbcAsync(PwsFileFieldType.DbName, Header.DbName);
            if (!string.IsNullOrEmpty(Header.DbDescription))
                await WriteUtf8CbcAsync(PwsFileFieldType.DbDesc, Header.DbDescription);
            // TODO: more stuff?
            foreach (var group in EmptyGroups)
                await WriteUtf8CbcAsync(PwsFileFieldType.EmptyGroup, group);

            // Write zero-length end-of-record type item
            await WriteCbcAsync(PwsFileFieldType.End, new byte[0], 0);
        }

        private async Task WriteCbcAsync(PwsFileFieldType type, byte[] data, int dataLen)
        {
            await WriteCbcAsync((byte) type, data, dataLen);
        }

        private async Task WriteUtf8CbcAsync(PwsFileFieldType type, string data)
        {
            var pdata = Encoding.UTF8.GetBytes(data);
            await WriteCbcAsync((byte) type, pdata, pdata.Length);
        }

        protected override Task WriteCbcAsync(byte type, byte[] data, int dataLen)
        {
            _hmac.TransformBlock(data, 0, dataLen, null, 0);
            return base.WriteCbcAsync(type, data, dataLen);
        }

        [SuppressMessage("ReSharper", "InconsistentNaming")]
        private async Task ReadHeaderAsync()
        {
            await SanityCheckAsync();
            var keyInfo = await CheckPasskeyAsync();


            using (var tf = new TwofishManagedTransform(keyInfo.Hash, CipherMode.ECB, null,
                TwofishManagedTransformMode.Decrypt, PaddingMode.None))
            {
                var b1b2 = new byte[_key.Length];
                await _stream.ReadAsync(b1b2, 0, b1b2.Length);
                tf.TransformBlock(b1b2, 0, 16, _key, 0);
                tf.TransformBlock(b1b2, 16, 16, _key, 16);


                var l = new byte[32];
                var b3b4 = new byte[l.Length];
                await _stream.ReadAsync(b3b4, 0, b3b4.Length);
                tf.TransformBlock(b3b4, 0, 16, l, 0);
                tf.TransformBlock(b3b4, 16, 16, l, 16);


                _hmac = new HMACSHA256(l);
                _hmac.Initialize();

                await _stream.ReadAsync(Ipthing, 0, Ipthing.Length);

                Fish = new TwofishManagedTransform(_key, CipherMode.ECB, null, TwofishManagedTransformMode.Decrypt,
                    PaddingMode.None);

                PwsRecord record;
                var found0302UserHost = false;
                do
                {
                    record = await ReadCbcAsync();
                    if (record.ReadBytes == 0)
                        continue;

                    switch ((PwsFileFieldType) record.Type)
                    {
                        case PwsFileFieldType.Version:
                            if (record.Buffer.Length != sizeof(short) &&
                                record.Buffer.Length != sizeof(int))
                                throw new NotSupportedException("Unknown record data");
                            if (record.Buffer[1] != (VersionNum & 0xFF00) >> 8)
                                throw new NotSupportedException("Unsupported version");
                            Header.Version = new Version(record.Buffer[1], record.Buffer[0]);
                            break;
                        case PwsFileFieldType.Uuid:
                            Header.Uuid = record.Buffer.ToGuid();
                            break;
                        case PwsFileFieldType.NdPrefs:
                            Header.PrefString = record.Buffer.Length != 0 ? Encoding.UTF8.GetString(record.Buffer) : "";
                            break;
                        case PwsFileFieldType.LastUpdateTime:
                            Header.WhenLastSaved = DateTime.MinValue;
                            if (record.Buffer.Length == 8)
                            {
                                // Handle pre-3.09 implementations that mistakenly
                                // stored this as a hex value
                                var text = Encoding.UTF8.GetString(record.Buffer);
                                try
                                {
                                    Header.WhenLastSaved = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) +
                                                         TimeSpan.FromSeconds(Convert.ToUInt32(text, 16));
                                }
                                catch
                                {
                                    // ignored
                                }
                            }

                            if (Header.WhenLastSaved == DateTime.MinValue)
                                if (record.Buffer.Length == 4)
                                    Header.WhenLastSaved =
                                        new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) +
                                        TimeSpan.FromSeconds(BitConverter.ToUInt32(record.Buffer, 0));
                                else if (record.Buffer.Length == 8)
                                    Header.WhenLastSaved =
                                        new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) +
                                        TimeSpan.FromSeconds(BitConverter.ToUInt64(record.Buffer, 0));
                            break;
                        case PwsFileFieldType.LastUpdateUserHost:
                            // DEPRECATED, but we still know how to read this
                            if (!found0302UserHost)
                            {
                                var text = Encoding.UTF8.GetString(record.Buffer);
                                var ulen = Convert.ToInt32(text.Substring(0, 4), 16);
                                var uh = text.Substring(4);
                                Header.LastSavedBy = uh.Substring(0, ulen);
                                Header.LastSavedOn = uh.Substring(ulen);
                            }
                            break;
                        case PwsFileFieldType.LastUpdateApplication:
                            Header.WhatLastSaved = Encoding.UTF8.GetString(record.Buffer);
                            break;
                        case PwsFileFieldType.LastUpdateUser:
                            found0302UserHost = true;
                            Header.LastSavedBy = Encoding.UTF8.GetString(record.Buffer);
                            break;
                        case PwsFileFieldType.LastUpdateHost:
                            found0302UserHost = true;
                            Header.LastSavedOn = Encoding.UTF8.GetString(record.Buffer);
                            break;
                        case PwsFileFieldType.DbName:
                            Header.DbName = Encoding.UTF8.GetString(record.Buffer);
                            break;
                        case PwsFileFieldType.DbDesc:
                            Header.DbDescription = Encoding.UTF8.GetString(record.Buffer);
                            break;
                        case PwsFileFieldType.EmptyGroup:
                            EmptyGroups.Add(Encoding.UTF8.GetString(record.Buffer));
                            break;
                        case PwsFileFieldType.End:
                            break;
                        // TODO: some other fields that might be useful (password policies)
                        default:
                            break;
                    }
                } while ((PwsFileFieldType) record.Type != PwsFileFieldType.End);
                EmptyGroups.Sort();
            }
        }

        private async Task<PwHashInfo> CheckPasskeyAsync()
        {
            

            _stream.Position += V3Tag.Length; // skip over tag

            var salt = new byte[PwSaltLength];
            await _stream.ReadAsync(salt, 0, salt.Length);

            var nb = new byte[sizeof(uint)];
            await _stream.ReadAsync(nb, 0, nb.Length);

            var n = BitConverter.ToUInt32(nb, 0);

            if (n < MinHashIterations)
                throw new Exception("Hash iterations insecure.");

            
            var usedPtag = StretchKey(salt, n);

            using (var h = SHA256.Create())
            {
                h.Initialize();
                var hpTag = h.ComputeHash(usedPtag, 0, Sha256HashLen);

                var readHpTag = new byte[Sha256HashLen];
                _stream.Read(readHpTag, 0, readHpTag.Length);
                if (!hpTag.SequenceEqual(readHpTag))
                    throw new UnauthorizedAccessException("Wrong password");
            }

            return new PwHashInfo
            {
                Hash = usedPtag
            };
        }

        private async Task SanityCheckAsync()
        {
            const long minV3FileLength = 232;

            var oldPos = _stream.Position;
            var length = _stream.Length - oldPos;
            try
            {
                if (length < V3Tag.Length)
                    throw new InvalidDataException("Not a PWS3 file.");
                if (!await IsV3X(_stream))
                    throw new InvalidDataException("File is not a V3 password safe.");

                if (length < minV3FileLength)
                    throw new InvalidDataException("Truncated file.");

                _stream.Seek(-(TerminalBlock.Length + Sha256HashLen), SeekOrigin.End);

                var eofBlock = new byte[TerminalBlock.Length];
                if (await _stream.ReadAsync(eofBlock, 0, eofBlock.Length) != eofBlock.Length)
                    throw new InvalidDataException("Truncated file.");
                if (!eofBlock.SequenceEqual(TerminalBlock))
                    throw new InvalidDataException("Truncated file.");
            }
            finally
            {
                _stream.Position = oldPos;
            }
        }

        private byte[] StretchKey(byte[] salt, uint n)
        {
            /*
             * P' is the "stretched key" of the user's passphrase and the SALT, as defined
             * by the hash-function-based key stretching algorithm in
             * http://www.schneier.com/paper-low-entropy.pdf (Section 4.1), with SHA-256
             * as the hash function, and N iterations.
             */
            byte[] x;
            unsafe
            {
                var pstrtemp = (char*) Marshal.SecureStringToGlobalAllocUnicode(_passkey);
                var pstr = (byte*) Marshal.AllocHGlobal(_passkey.Length + salt.Length);
                var pstrlen = Encoding.GetEncoding(1252).GetBytes(pstrtemp, _passkey.Length, pstr, _passkey.Length);
                Marshal.Copy(salt, 0, new IntPtr(pstr + pstrlen), salt.Length);

                using (var h0 = SHA256.Create())
                {
                    h0.Initialize();
                    using (var pwstream = new UnmanagedMemoryStream(pstr, pstrlen + salt.Length))
                    {
                        x = h0.ComputeHash(pwstream);
                    }
                }

                Marshal.ZeroFreeGlobalAllocAnsi(new IntPtr(pstr));
                Marshal.ZeroFreeGlobalAllocAnsi(new IntPtr(pstrtemp));
            }

            if (n < MinHashIterations)
                throw new InvalidOperationException("iterations too small");

            using (var h = SHA256.Create())
            {
                h.Initialize();
                for (uint i = 0; i < n; i++)
                    x = h.ComputeHash(x, 0, Sha256HashLen);
            }
            return x;
        }

        protected override async Task<PwsRecord> ReadCbcAsync()
        {
            var result = await base.ReadCbcAsync();

            if (result != null && result.ReadBytes > 0)
                _hmac.TransformBlock(result.Buffer, 0, result.Buffer.Length, null, 0);

            return result;
        }

        /// <summary>
        /// Determines if the given stream contains a version 3 password safe.
        /// </summary>
        /// <param name="stream">Stream to read from.</param>
        /// <param name="rewind">If set to true will rewind to original stream position after detection.</param>
        /// <returns>true, if the stream contains a v3 safe.</returns>
        public static async Task<bool> IsV3X(Stream stream, bool rewind = true)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            var oldPos = stream.Position;

            try
            {
                var buffer = new byte[4];
                if (await stream.ReadAsync(buffer, 0, 4) != 4)
                    return false;

                return buffer.SequenceEqual(V3Tag);
            }
            finally
            {
                if (rewind)
                {
                    stream.Position = oldPos;
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hmac.TransformFinalBlock(new byte[0], 0, 0);
                var digest = _hmac.Hash;

                if (_fileMode == FileMode.Create)
                {
                    _stream.Write(TerminalBlock, 0, TerminalBlock.Length);
                    _stream.Write(digest, 0, digest.Length);
                }
                else // read
                {
                    var d = new byte[Sha256HashLen];
                    _stream.Read(d, 0, d.Length);
                    if (!d.SequenceEqual(digest))
                    {
                        base.Dispose(true);
                        throw new BadDigestException();
                    }
                }
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// Writes an item data record to the safe.
        /// </summary>
        /// <param name="item">Data to write.</param>
        public async Task WriteRecordAsync(ItemData item)
        {
            await item.WriteAsync(this);
        }

        /// <summary>
        /// Reads an item data record from the safe.
        /// </summary>
        /// <returns><see cref="ItemData"/> record or null, if no more records found (EOF).</returns>
        public async Task<ItemData> ReadRecordAsync()
        {
            var item = new ItemData();
            if (!await item.ReadAsync(this))
                return null;
            return item;
        }

        private class PwHashInfo
        {
            public byte[] Hash { get; set; }
        }


        private enum PwsFileFieldType
        {
            Version = 0,
            Uuid = 1,

            /// <summary>
            ///     Non-default user preferences
            /// </summary>
            NdPrefs = 2,

            /// <summary>
            ///     Tree Display Status
            /// </summary>
            // ReSharper disable once UnusedMember.Local
            DispStat = 3,

            /// <summary>
            ///     When last saved
            /// </summary>
            LastUpdateTime = 4,

            /// <summary>
            ///     Last Update host
            /// </summary>
            LastUpdateUserHost = 5,
            LastUpdateApplication = 6,
            LastUpdateUser = 7,
            LastUpdateHost = 8,
            DbName = 9,
            DbDesc = 10,
            EmptyGroup = 17,
            End = 255
        }
    }
}