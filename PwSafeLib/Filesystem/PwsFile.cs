using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using PwSafeLib.Crypto;
using PwSafeLib.Helper;

namespace PwSafeLib.Filesystem
{
    public enum PwsFileVersion
    {
        Unknown,
        Version3,
        Version4
    }

    public class PwsRecord
    {
        public byte[] Buffer { get; set; }
        public byte Type { get; set; }

        public int ReadBytes { get; set; }
    }

    public abstract class PwsFile : IDisposable
    {
        public const uint MinHashIterations = 2048;
        protected readonly byte[] Ipthing = new byte[16];

        protected readonly Stream _stream;
        protected List<string> EmptyGroups = new List<string>();

        protected FileMode _fileMode;
        internal TwofishManagedTransform Fish;

        private readonly byte[] _terminalBlock;

        protected PwsFile(Stream stream, byte[] terminalBlock, FileMode fileMode)
        {
            _terminalBlock = terminalBlock;
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _fileMode = fileMode;
        }

        /// <summary>
        /// File Header of the current password safe.
        /// </summary>
        public PwsFileHeader Header { get; set; } = new PwsFileHeader();

        /// <summary>
        /// Sets the application name, that is written to every password safe file.
        /// </summary>
        public static string ApplicationName { get; set; } = ".Net PasswordSafe";

        internal abstract int TimeFieldLen { get; }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Opens a password safe file of any supported version. A call to the corresponding OpenAsync
        /// methods is not neccessary after this.
        /// </summary>
        /// <param name="stream">Stream to read the password safe data from.</param>
        /// <param name="passkey">Plain text password for the safe.</param>
        /// <returns>An instance of a password safe file (<see cref="PwsFileV3"/>, <see cref="PwsFileV4"/>).</returns>
        /// <exception cref="UnauthorizedAccessException">The given password for the container is wrong.</exception>
        /// <exception cref="NotSupportedException">Container version is not supported.</exception>
        public static async Task<PwsFile> OpenAsync(Stream stream, SecureString passkey)
        {
            var version = await ReadVersionAsync(stream);
            PwsFile file;
            switch (version)
            {
                case PwsFileVersion.Version3:
                    file = new PwsFileV3(stream, passkey);
                    break;
                default:
                    throw new NotSupportedException("Requested container version is not supported.");
            }
            await file.OpenAsync();
            return file;
        }

        /// <summary>
        /// Creates a new password safe with the given file version.
        /// </summary>
        /// <param name="stream">Stream to write the safe to.</param>
        /// <param name="passkey">Plain text password for the safe.</param>
        /// <param name="version">Version of the password safe to use. The result object type depends on that.</param>
        /// <returns>An empty password safe instance.</returns>
        /// <exception cref="NotSupportedException">Container version is not supported.</exception>
        public static async Task<PwsFile> CreateAsync(Stream stream, SecureString passkey, PwsFileVersion version)
        {
            PwsFile file;
            switch (version)
            {
                case PwsFileVersion.Version3:
                    file = new PwsFileV3(stream, passkey, FileMode.Create);
                    break;
                default:
                    throw new NotSupportedException("Requested container version is not supported.");
            }
            await file.OpenAsync();
            return file;
        }

        /// <summary>
        /// Opens the password safe for reading or writing. This is only needed, if the object wasn't created
        /// by <see cref="OpenAsync(System.IO.Stream,System.Security.SecureString)"/> or <see cref="CreateAsync"/>.
        /// </summary>
        public abstract Task OpenAsync();

        private static async Task<PwsFileVersion> ReadVersionAsync(Stream stream)
        {
            if (await PwsFileV3.IsV3X(stream))
                return PwsFileVersion.Version3;
            return PwsFileVersion.Unknown;
        }

        protected virtual async Task<PwsRecord> ReadCbcAsync()
        {
            return await ReadCbcInternalAsync(Fish, _terminalBlock);
        }

        protected virtual async Task WriteCbcAsync(byte type, byte[] data, int dataLen)
        {
            await WriteCbcInternalAsync(type, data, dataLen, Fish);
        }

        private async Task WriteCbcInternalAsync(byte type, byte[] buffer, int length, ICryptoTransform algorithm)
        {
            var bs = algorithm.OutputBlockSize;
            var block1 = new byte[16];

            var curblock = block1;
            try
            {
                var bufferIdx = 0;

                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(curblock);
                }

                // block length overwrites 4 bytes of the above randomness.
                var len = BitConverter.GetBytes(length);
                Array.Copy(len, curblock, len.Length);

                // following new for format 2.0 - lengthblock bytes 4-7 were unused before.
                curblock[sizeof(int)] = type;

                if (bs == 16)
                {
                    // In this case, we've too many (11) wasted bytes in the length block
                    // So we store actual data there:
                    // (11 = BlockSize - 4 (length) - 1 (type)
                    var len1 = length > 11 ? 11 : length;
                    Array.Copy(buffer, 0, curblock, 5, len1);
                    length -= len1;
                    bufferIdx += len1;
                }

                XorArray(curblock, Ipthing, bs); // do the CBC thing
                algorithm.TransformBlock(curblock, 0, 16, curblock, 0);
                Array.Copy(curblock, Ipthing, bs); // update CBC for next round

                await _stream.WriteAsync(curblock, 0, bs);

                await WriteCbcInternalAsync(buffer, bufferIdx, length, algorithm);
            }
            finally
            {
                PwsUtil.TrashMemory(curblock);
            }
        }

        private async Task WriteCbcInternalAsync(byte[] buffer, int bufferIdx, int length, ICryptoTransform algorithm)
        {
            var bs = algorithm.OutputBlockSize;
            var block1 = new byte[16];

            var curblock = block1;
            try
            {
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(curblock);

                    if (length > 0 ||
                        bs == 8 && length == 0) // This part for bwd compat w/pre-3 format)
                    {
                        var blockLength = (length + (bs - 1)) / bs * bs;
                        if (blockLength == 0 && bs == 8)
                            blockLength = bs;

                        // Now, encrypt and write the (rest of the) buffer
                        for (var x = 0; x < blockLength; x += bs)
                        {
                            if (length == 0 || length % bs != 0 && length - x < bs)
                            {
                                //This is for an uneven last block
                                rng.GetBytes(curblock);
                                Array.Copy(buffer, bufferIdx + x, curblock, 0, length % bs);
                            }
                            else
                            {
                                Array.Copy(buffer, bufferIdx + x, curblock, 0, bs);
                            }
                            XorArray(curblock, Ipthing, bs);
                            algorithm.TransformBlock(curblock, 0, 16, curblock, 0);
                            Array.Copy(curblock, Ipthing, bs);

                            await _stream.WriteAsync(curblock, 0, bs);
                        }
                    }
                }
            }
            finally
            {
                PwsUtil.TrashMemory(curblock);
            }
        }

        /*
        * Reads an encrypted record into buffer.
        * The first block of the record contains the encrypted record length
        * We have the usual ugly problem of fixed buffer lengths in C/C++.
        * allocate the buffer here, to ensure that it's long enough.
        * *** THE CALLER MUST delete[] IT AFTER USE *** UGH++
        *
        * (unless buffer_len is zero)
        *
        * Note that the buffer is a byte array, and buffer_len is number of
        * bytes. This means that any data can be passed, and we don't
        * care at this level if strings are char or wchar_t.
        *
        * If TERMINAL_BLOCK is non-NULL, the first block read is tested against it,
        * and -1 is returned if it matches. (used in V3)
        */
        private async Task<PwsRecord> ReadCbcInternalAsync(ICryptoTransform algorithm,
            byte[] terminalBlock)
        {
            var bs = algorithm.InputBlockSize;
            var block1 = new byte[16];
            var block2 = new byte[16];
            var block3 = new byte[16];
            var lengthblock = block1;
            var numRead = await _stream.ReadAsync(lengthblock, 0, bs);
            if (numRead != bs)
                return null;

            if (terminalBlock != null && lengthblock.SequenceEqual(terminalBlock))
                return null;

            var lcpy = block2;
            Array.Copy(lengthblock, lcpy, bs);


            algorithm.TransformBlock(lengthblock, 0, lengthblock.Length, lengthblock, 0);
            XorArray(lengthblock, Ipthing, bs);
            Array.Copy(lcpy, Ipthing, bs);

            var length = BitConverter.ToUInt32(lengthblock, 0);

            var result = new PwsRecord();
            // new for 2.0 -- lengthblock[4..7] previously set to zero
            result.Type = lengthblock[sizeof(int)]; // type is first byte after the length

            if (_stream.Length != 0 && length >= _stream.Length)
            {
                PwsUtil.TrashMemory(lengthblock);
                return null;
            }

            var bufferLen = length;
            var buffer = new byte[length / bs * bs + 2 * bs]; // round upwards
            var bufferidx = 0;

            if (bs == 16)
            {
                // length block contains up to 11 (= 16 - 4 - 1) bytes
                // of data
                var len1 = length > 11 ? 11 : length;
                Array.Copy(lengthblock, 5, buffer, bufferidx, (int) len1);
                length -= len1;
                bufferidx += (int) len1;
            }

            var blockLength = (length + (bs - 1)) / bs * bs;
            // Following is meant for lengths < BS,
            // but results in a block being read even
            // if length is zero. This is wasteful,
            // but fixing it would break all existing pre-3.0 databases.
            if (blockLength == 0 && bs == 8)
                blockLength = bs;

            PwsUtil.TrashMemory(lengthblock);

            if (length > 0 || bs == 8 && length == 0)
            {
                // pre-3 pain
                var tempcbc = block3;
                numRead += await _stream.ReadAsync(buffer, bufferidx, (int) blockLength);
                for (var x = 0; x < blockLength; x += bs)
                {
                    Array.Copy(buffer, bufferidx + x, tempcbc, 0, bs);
                    algorithm.TransformBlock(buffer, bufferidx + x, 16, buffer, bufferidx + x);
                    XorArray(buffer, bufferidx + x, Ipthing, 0, bs);
                    Array.Copy(tempcbc, Ipthing, bs);
                }
            }

            if (bufferLen == 0)
            {
                result.Buffer = new byte[0];
            }
            else
            {
                result.Buffer = new byte[bufferLen];
                Array.Copy(buffer, result.Buffer, (int) bufferLen);
                PwsUtil.TrashMemory(buffer);
            }
            result.ReadBytes = numRead;

            return result;
        }

     
        protected static byte[] HashRandom256()
        {
            var result = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(result);
            }
            using (var salter = SHA256.Create())
            {
                salter.Initialize();
                result = salter.ComputeHash(result);
            }
            return result;
        }

        internal async Task<PwsRecord> ReadFieldAsync()
        {
            return await ReadCbcAsync();
        }

        internal async Task WriteFieldAsync(Item.FieldType type, byte[] data)
        {
            await WriteCbcAsync((byte) type, data, data.Length);
        }


        private static void XorArray(byte[] mem1, byte[] mem2, int length)
        {
            for (var x = 0; x < length; x++)
                mem1[x] ^= mem2[x];
        }

        private static void XorArray(byte[] mem1, int mem1Idx, byte[] mem2, int mem2Idx, int length)
        {
            for (var x = mem1Idx; x < length + mem1Idx; x++)
                mem1[x] ^= mem2[x - mem1Idx + mem2Idx];
        }


        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
                Fish?.Dispose();
        }

        
    }
}