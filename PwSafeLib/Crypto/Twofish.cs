using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PwSafeLib.Crypto
{
    /// <summary>
    ///     Twofish algorithm implementation.
    ///     This class cannot be inherited.
    /// </summary>
    /// <remarks>https://www.schneier.com/twofish.html</remarks>
    sealed class TwofishManaged : SymmetricAlgorithm
    {
        /// <summary>
        ///     Initializes a new instance.
        /// </summary>
        public TwofishManaged()
        {
            KeySizeValue = 256;
            BlockSizeValue = 128;
            // base.FeedbackSizeValue = base.BlockSizeValue;
            LegalBlockSizesValue = new[] {new KeySizes(128, 128, 0)};
            LegalKeySizesValue = new[] {new KeySizes(128, 256, 64)};

            base.Mode = CipherMode.CBC; //same as default
            base.Padding = PaddingMode.PKCS7;
        }


        /// <summary>
        ///     Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override CipherMode Mode
        {
            get => base.Mode;
            set
            {
                if (value != CipherMode.CBC && value != CipherMode.ECB)
                    throw new CryptographicException("Cipher mode is not supported.");
                base.Mode = value;
            }
        }

        /// <summary>
        ///     Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        public override PaddingMode Padding
        {
            get => base.Padding;
            set
            {
                if (value != PaddingMode.None && value != PaddingMode.PKCS7 && value != PaddingMode.Zeros)
                    throw new CryptographicException("Padding mode is not supported.");
                base.Padding = value;
            }
        }


        /// <summary>
        ///     Creates a symmetric decryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIV">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null) throw new ArgumentNullException("rgbKey", "Key cannot be null.");
            if (rgbKey.Length != KeySize / 8) throw new ArgumentOutOfRangeException("rgbKey", "Key size mismatch.");
            if (Mode == CipherMode.CBC)
            {
                if (rgbIV == null) throw new ArgumentNullException("rgbIV", "IV cannot be null.");
                if (rgbIV.Length != 16) throw new ArgumentOutOfRangeException("rgbIV", "Invalid IV size.");
            }

            return NewEncryptor(rgbKey, Mode, rgbIV, TwofishManagedTransformMode.Decrypt);
        }

        /// <summary>
        ///     Creates a symmetric encryptor object.
        /// </summary>
        /// <param name="rgbKey">The secret key to be used for the symmetric algorithm. The key size must be 128, 192, or 256 bits.</param>
        /// <param name="rgbIV">The IV to be used for the symmetric algorithm.</param>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null) throw new ArgumentNullException("rgbKey", "Key cannot be null.");
            if (rgbKey.Length != KeySize / 8) throw new ArgumentOutOfRangeException("rgbKey", "Key size mismatch.");
            if (Mode == CipherMode.CBC)
            {
                if (rgbIV == null) throw new ArgumentNullException("rgbIV", "IV cannot be null.");
                if (rgbIV.Length != 16) throw new ArgumentOutOfRangeException("rgbIV", "Invalid IV size.");
            }

            return NewEncryptor(rgbKey, Mode, rgbIV, TwofishManagedTransformMode.Encrypt);
        }

        /// <summary>
        ///     Generates a random initialization vector to be used for the algorithm.
        /// </summary>
        public override void GenerateIV()
        {
            IVValue = new byte[BlockSizeValue / 8];
            Rng.GetBytes(IVValue);
        }

        /// <summary>
        ///     Generates a random key to be used for the algorithm.
        /// </summary>
        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeValue / 8];
            Rng.GetBytes(KeyValue);
        }


        #region Private

        [ThreadStatic] private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        private ICryptoTransform NewEncryptor(byte[] rgbKey, CipherMode mode, byte[] rgbIV,
            TwofishManagedTransformMode encryptMode)
        {
            if (rgbKey == null)
            {
                rgbKey = new byte[KeySize / 8];
                Rng.GetBytes(rgbKey);
            }

            if (mode != CipherMode.ECB && rgbIV == null)
            {
                rgbIV = new byte[KeySize / 8];
                Rng.GetBytes(rgbIV);
            }

            return new TwofishManagedTransform(rgbKey, mode, rgbIV, encryptMode, Padding);
        }

        #endregion
    }


    /// <summary>
    ///     Performs a cryptographic transformation of data using the Twofish algorithm.
    ///     This class cannot be inherited.
    /// </summary>
    internal sealed class TwofishManagedTransform : ICryptoTransform
    {
        private readonly PaddingMode _paddingMode;


        private readonly TwofishManagedTransformMode _transformMode;

        private readonly TwofishImplementation _implementation;


        private byte[] _paddingBuffer; //used to store last block block under decrypting as to work around CryptoStream implementation details.

        internal TwofishManagedTransform(byte[] key, CipherMode mode, byte[] iv,
            TwofishManagedTransformMode transformMode, PaddingMode paddingMode)
        {
            _transformMode = transformMode;
            _paddingMode = paddingMode;

            var key32 = new uint[key.Length / 4];
            Buffer.BlockCopy(key, 0, key32, 0, key.Length);

            if (iv != null)
            {
                var iv32 = new uint[iv.Length / 4];
                Buffer.BlockCopy(iv, 0, iv32, 0, iv.Length);
                _implementation = new TwofishImplementation(key32, iv32, mode);
            }
            else
            {
                _implementation = new TwofishImplementation(key32, null, mode);
            }
        }


        /// <summary>
        ///     Gets a value indicating whether the current transform can be reused.
        /// </summary>
        public bool CanReuseTransform => false;

        /// <summary>
        ///     Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        public bool CanTransformMultipleBlocks => true;

        /// <summary>
        ///     Gets the input block size (in bytes).
        /// </summary>
        public int InputBlockSize //block is always 128 bits
            => 16;

        /// <summary>
        ///     Gets the output block size (in bytes).
        /// </summary>
        public int OutputBlockSize //block is always 128 bits
            => 16;

        /// <summary>
        ///     Releases resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }


        /// <summary>
        ///     Transforms the specified region of the input byte array and copies the resulting transform to the specified region
        ///     of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write the transform.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        [SuppressMessage("Microsoft.Usage", "CA2233:OperationsShouldNotOverflow", MessageId = "outputOffset+16",
            Justification = "Value will never cause the arithmetic operation to overflow.")]
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
            int outputOffset)
        {
            if (inputBuffer == null) throw new ArgumentNullException("inputBuffer", "Input buffer cannot be null.");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "Offset must be non-negative number.");
            if (inputCount <= 0 || inputCount % 16 != 0 || inputCount > inputBuffer.Length)
                throw new ArgumentOutOfRangeException("inputCount", "Invalid input count.");
            if (inputBuffer.Length - inputCount < inputOffset)
                throw new ArgumentOutOfRangeException("inputCount", "Invalid input length.");
            if (outputBuffer == null) throw new ArgumentNullException("outputBuffer", "Output buffer cannot be null.");
            if (outputOffset + inputCount > outputBuffer.Length)
                throw new ArgumentOutOfRangeException("outputOffset", "Insufficient buffer.");

            if (_transformMode == TwofishManagedTransformMode.Encrypt)
            {
                #region Encrypt

                for (var i = 0; i < inputCount; i += 16)
                    _implementation.BlockEncrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset + i);
                return inputCount;

                #endregion
            }

            #region Decrypt

            var bytesWritten = 0;

            if (_paddingBuffer != null)
            {
                _implementation.BlockDecrypt(_paddingBuffer, 0, outputBuffer, outputOffset);
                outputOffset += 16;
                bytesWritten += 16;
            }

            for (var i = 0; i < inputCount - 16; i += 16)
            {
                _implementation.BlockDecrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset);
                outputOffset += 16;
                bytesWritten += 16;
            }

            if (_paddingMode == PaddingMode.None)
            {
                _implementation.BlockDecrypt(inputBuffer, inputOffset + inputCount - 16, outputBuffer, outputOffset);
                bytesWritten += 16;
            }
            else
            {
                //save last block without processing because decryption otherwise cannot detect padding in CryptoStream
                if (_paddingBuffer == null) _paddingBuffer = new byte[16];
                Buffer.BlockCopy(inputBuffer, inputOffset + inputCount - 16, _paddingBuffer, 0, 16);
            }

            return bytesWritten;

            #endregion
        }

        /// <summary>
        ///     Transforms the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null) throw new ArgumentNullException("inputBuffer", "Input buffer cannot be null.");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "Offset must be non-negative number.");
            if (inputCount < 0 || inputCount > inputBuffer.Length)
                throw new ArgumentOutOfRangeException("inputCount", "Invalid input count.");
            if (inputBuffer.Length - inputCount < inputOffset)
                throw new ArgumentOutOfRangeException("inputCount", "Invalid input length.");

            if (_transformMode == TwofishManagedTransformMode.Encrypt)
            {
                #region Encrypt

                int paddedLength;
                byte[] paddedInputBuffer;
                int paddedInputOffset;
                if (_paddingMode == PaddingMode.PKCS7)
                {
                    paddedLength = inputCount / 16 * 16 + 16; //to round to next whole block
                    paddedInputBuffer = new byte[paddedLength];
                    paddedInputOffset = 0;
                    Buffer.BlockCopy(inputBuffer, inputOffset, paddedInputBuffer, 0, inputCount);
                    var added = (byte) (paddedLength - inputCount);
                    for (var i = inputCount; i < inputCount + added; i++)
                        paddedInputBuffer[i] = added;
                }
                else if (_paddingMode == PaddingMode.Zeros)
                {
                    paddedLength = (inputCount + 15) / 16 * 16; //to round to next whole block
                    paddedInputBuffer = new byte[paddedLength];
                    paddedInputOffset = 0;
                    Buffer.BlockCopy(inputBuffer, inputOffset, paddedInputBuffer, 0, inputCount);
                }
                else
                {
                    if (inputCount % 16 != 0)
                        throw new ArgumentOutOfRangeException("inputCount", "Invalid input count for a given padding.");
                    paddedLength = inputCount;
                    paddedInputBuffer = inputBuffer;
                    paddedInputOffset = inputOffset;
                }

                var outputBuffer = new byte[paddedLength];

                for (var i = 0; i < paddedLength; i += 16)
                    _implementation.BlockEncrypt(paddedInputBuffer, paddedInputOffset + i, outputBuffer, i);

                return outputBuffer;

                #endregion
            }
            else
            {
                #region Decrypt

                if (inputCount % 16 != 0) throw new ArgumentOutOfRangeException("inputCount", "Invalid input count.");

                var outputBuffer = new byte[inputCount + (_paddingBuffer != null ? 16 : 0)];
                var outputOffset = 0;

                if (_paddingBuffer != null)
                {
                    //process leftover padding buffer to keep CryptoStream happy
                    _implementation.BlockDecrypt(_paddingBuffer, 0, outputBuffer, 0);
                    outputOffset = 16;
                }

                for (var i = 0; i < inputCount; i += 16)
                    _implementation.BlockDecrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset + i);

                if (_paddingMode == PaddingMode.PKCS7)
                {
                    var padding = outputBuffer[outputBuffer.Length - 1];
                    if (padding < 1 || padding > 16) throw new CryptographicException("Invalid padding.");
                    for (var i = outputBuffer.Length - padding; i < outputBuffer.Length; i++)
                        if (outputBuffer[i] != padding) throw new CryptographicException("Invalid padding.");
                    var newOutputBuffer = new byte[outputBuffer.Length - padding];
                    Buffer.BlockCopy(outputBuffer, 0, newOutputBuffer, 0, newOutputBuffer.Length);
                    return newOutputBuffer;
                }
                if (_paddingMode == PaddingMode.Zeros)
                {
                    var newOutputLength = outputBuffer.Length;
                    for (var i = outputBuffer.Length - 1; i >= outputBuffer.Length - 16; i--)
                        if (outputBuffer[i] != 0)
                        {
                            newOutputLength = i + 1;
                            break;
                        }
                    if (newOutputLength == outputBuffer.Length)
                        return outputBuffer;
                    var newOutputBuffer = new byte[newOutputLength];
                    Buffer.BlockCopy(outputBuffer, 0, newOutputBuffer, 0, newOutputBuffer.Length);
                    return newOutputBuffer;
                }
                return outputBuffer;

                #endregion
            }
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                _implementation.Dispose();
                if (_paddingBuffer != null) Array.Clear(_paddingBuffer, 0, _paddingBuffer.Length);
            }
        }


        private class TwofishImplementation : IDisposable
        {
            private const int BlockSize = 128; //number of bits per block
            private const int Rounds = 16; //default number of rounds for 128/192/256-bit keys
            private const int MaxKeyBits = 256; //max number of bits of key

            private const int InputWhiten = 0;
            private const int OutputWhiten = InputWhiten + BlockSize / 32;
            private const int RoundSubkeys = OutputWhiten + BlockSize / 32;
            private const int TotalSubkeys = RoundSubkeys + 2 * Rounds;
            private readonly CipherMode _cipherMode;
            private readonly DWord[] _iv;

            private readonly DWord[] _key;

            private readonly DWord[] _sBoxKeys = new DWord[MaxKeyBits / 64]; //key bits used for S-boxes
            private readonly DWord[] _subKeys = new DWord[TotalSubkeys]; //round subkeys, input/output whitening bits

            public TwofishImplementation(uint[] key, uint[] iv, CipherMode cipherMode)
            {
                _key = new DWord[key.Length];
                for (var i = 0; i < _key.Length; i++)
                    _key[i] = (DWord) key[i];

                if (iv != null)
                {
                    _iv = new DWord[iv.Length];
                    for (var i = 0; i < _iv.Length; i++)
                        _iv[i] = (DWord) iv[i];
                }

                _cipherMode = cipherMode;

                ReKey();
            }


            public void Dispose()
            {
                Array.Clear(_key, 0, _key.Length);
                if (_iv != null) Array.Clear(_iv, 0, _iv.Length);
                Array.Clear(_sBoxKeys, 0, _sBoxKeys.Length);
                Array.Clear(_subKeys, 0, _subKeys.Length);
            }


            [DebuggerDisplay("{Value}")]
            [StructLayout(LayoutKind.Explicit)]
            private struct DWord
            {
                //makes extracting bytes from uint faster and looks better
                [FieldOffset(0)] public byte B0;

                [FieldOffset(1)] public byte B1;
                [FieldOffset(2)] public byte B2;
                [FieldOffset(3)] public byte B3;

                [FieldOffset(0)] private uint Value;

                private DWord(uint value) : this()
                {
                    Value = value;
                }

                internal DWord(byte[] buffer, int offset) : this()
                {
                    B0 = buffer[offset + 0];
                    B1 = buffer[offset + 1];
                    B2 = buffer[offset + 2];
                    B3 = buffer[offset + 3];
                }


                public static explicit operator uint(DWord expr)
                {
                    return expr.Value;
                }


                public static explicit operator DWord(int value)
                {
                    return new DWord((uint) value);
                }

                public static explicit operator DWord(uint value)
                {
                    return new DWord(value);
                }


                public static DWord operator +(DWord expr1, DWord expr2)
                {
                    expr1.Value += expr2.Value;
                    return expr1;
                }

                public static DWord operator *(uint value, DWord expr)
                {
                    expr.Value = value * expr.Value;
                    return expr;
                }


                public static DWord operator |(DWord expr1, DWord expr2)
                {
                    expr1.Value |= expr2.Value;
                    return expr1;
                }

                public static DWord operator ^(DWord expr1, DWord expr2)
                {
                    expr1.Value ^= expr2.Value;
                    return expr1;
                }

                public static DWord operator <<(DWord expr, int count)
                {
                    expr.Value <<= count;
                    return expr;
                }

                public static DWord operator >>(DWord expr, int count)
                {
                    expr.Value >>= count;
                    return expr;
                }
            }


            #region ReKey

            private const int SubkeyStep = 0x02020202;
            private const int SubkeyBump = 0x01010101;
            private const int SubkeyRotateLeft = 9;

            /// <summary>
            ///     Initialize the Twofish key schedule from key32
            /// </summary>
            private void ReKey()
            {
                BuildMds(); //built only first time it is accessed

                var k32e = new DWord[_key.Length / 2];
                var k32o = new DWord[_key.Length / 2]; //even/odd key dwords

                var k64Cnt = _key.Length / 2;
                for (var i = 0; i < k64Cnt; i++)
                {
                    //split into even/odd key dwords
                    k32e[i] = _key[2 * i];
                    k32o[i] = _key[2 * i + 1];
                    _sBoxKeys[k64Cnt - 1 - i] =
                        ReedSolomonMdsEncode(k32e[i],
                            k32o[i]); //compute S-box keys using (12,8) Reed-Solomon code over GF(256)
                }

                var subkeyCnt = RoundSubkeys + 2 * Rounds;
                var keyLen = _key.Length * 4 * 8;
                for (var i = 0; i < subkeyCnt / 2; i++)
                {
                    //compute round subkeys for PHT
                    var A = F32((DWord) (i * SubkeyStep), k32e, keyLen); //A uses even key dwords
                    var B = F32((DWord) (i * SubkeyStep + SubkeyBump), k32o, keyLen); //B uses odd  key dwords
                    B = RotateLeft(B, 8);
                    _subKeys[2 * i] = A + B; //combine with a PHT
                    _subKeys[2 * i + 1] = RotateLeft(A + 2 * B, SubkeyRotateLeft);
                }
            }

            #endregion


            #region Encrypt/decrypt

            /// <summary>
            ///     Encrypt block(s) of data using Twofish.
            /// </summary>
            internal void BlockEncrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputBufferOffset)
            {
                var x = new DWord[BlockSize / 32];
                for (var i = 0; i < BlockSize / 32; i++)
                {
                    //copy in the block, add whitening
                    x[i] = new DWord(inputBuffer, inputOffset + i * 4) ^ _subKeys[InputWhiten + i];
                    if (_cipherMode == CipherMode.CBC) x[i] ^= _iv[i];
                }

                var keyLen = _key.Length * 4 * 8;
                for (var r = 0; r < Rounds; r++)
                {
                    //main Twofish encryption loop
                    var t0 = F32(x[0], _sBoxKeys, keyLen);
                    var t1 = F32(RotateLeft(x[1], 8), _sBoxKeys, keyLen);

                    x[3] = RotateLeft(x[3], 1);
                    x[2] ^= t0 + t1 + _subKeys[RoundSubkeys + 2 * r]; //PHT, round keys
                    x[3] ^= t0 + 2 * t1 + _subKeys[RoundSubkeys + 2 * r + 1];
                    x[2] = RotateRight(x[2], 1);

                    if (r < Rounds - 1)
                    {
                        //swap for next round
                        var tmp = x[0];
                        x[0] = x[2];
                        x[2] = tmp;
                        tmp = x[1];
                        x[1] = x[3];
                        x[3] = tmp;
                    }
                }

                for (var i = 0; i < BlockSize / 32; i++)
                {
                    //copy out, with whitening
                    var outValue = x[i] ^ _subKeys[OutputWhiten + i];
                    outputBuffer[outputBufferOffset + i * 4 + 0] = outValue.B0;
                    outputBuffer[outputBufferOffset + i * 4 + 1] = outValue.B1;
                    outputBuffer[outputBufferOffset + i * 4 + 2] = outValue.B2;
                    outputBuffer[outputBufferOffset + i * 4 + 3] = outValue.B3;
                    if (_cipherMode == CipherMode.CBC) _iv[i] = outValue;
                }
            }

            /// <summary>
            ///     Decrypt block(s) of data using Twofish.
            /// </summary>
            internal void BlockDecrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputBufferOffset)
            {
                var x = new DWord[BlockSize / 32];
                var input = new DWord[BlockSize / 32];
                for (var i = 0; i < BlockSize / 32; i++)
                {
                    //copy in the block, add whitening
                    input[i] = new DWord(inputBuffer, inputOffset + i * 4);
                    x[i] = input[i] ^ _subKeys[OutputWhiten + i];
                }

                var keyLen = _key.Length * 4 * 8;
                for (var r = Rounds - 1; r >= 0; r--)
                {
                    //main Twofish decryption loop
                    var t0 = F32(x[0], _sBoxKeys, keyLen);
                    var t1 = F32(RotateLeft(x[1], 8), _sBoxKeys, keyLen);

                    x[2] = RotateLeft(x[2], 1);
                    x[2] ^= t0 + t1 + _subKeys[RoundSubkeys + 2 * r]; //PHT, round keys
                    x[3] ^= t0 + 2 * t1 + _subKeys[RoundSubkeys + 2 * r + 1];
                    x[3] = RotateRight(x[3], 1);

                    if (r > 0)
                    {
                        //unswap, except for last round
                        t0 = x[0];
                        x[0] = x[2];
                        x[2] = t0;
                        t1 = x[1];
                        x[1] = x[3];
                        x[3] = t1;
                    }
                }

                for (var i = 0; i < BlockSize / 32; i++)
                {
                    //copy out, with whitening
                    x[i] ^= _subKeys[InputWhiten + i];
                    if (_cipherMode == CipherMode.CBC)
                    {
                        x[i] ^= _iv[i];
                        _iv[i] = input[i];
                    }
                    outputBuffer[outputBufferOffset + i * 4 + 0] = x[i].B0;
                    outputBuffer[outputBufferOffset + i * 4 + 1] = x[i].B1;
                    outputBuffer[outputBufferOffset + i * 4 + 2] = x[i].B2;
                    outputBuffer[outputBufferOffset + i * 4 + 3] = x[i].B3;
                }
            }

            #endregion


            #region F32

            /// <summary>
            ///     Run four bytes through keyed S-boxes and apply MDS matrix.
            /// </summary>
            private static DWord F32(DWord x, DWord[] k32, int keyLen)
            {
                if (keyLen >= 256)
                {
                    x.B0 = (byte) (P8x8[P_04, x.B0] ^ k32[3].B0);
                    x.B1 = (byte) (P8x8[P_14, x.B1] ^ k32[3].B1);
                    x.B2 = (byte) (P8x8[P_24, x.B2] ^ k32[3].B2);
                    x.B3 = (byte) (P8x8[P_34, x.B3] ^ k32[3].B3);
                }
                if (keyLen >= 192)
                {
                    x.B0 = (byte) (P8x8[P_03, x.B0] ^ k32[2].B0);
                    x.B1 = (byte) (P8x8[P_13, x.B1] ^ k32[2].B1);
                    x.B2 = (byte) (P8x8[P_23, x.B2] ^ k32[2].B2);
                    x.B3 = (byte) (P8x8[P_33, x.B3] ^ k32[2].B3);
                }
                if (keyLen >= 128)
                    x = MdsTable[0, P8x8[P_01, P8x8[P_02, x.B0] ^ k32[1].B0] ^ k32[0].B0]
                        ^ MdsTable[1, P8x8[P_11, P8x8[P_12, x.B1] ^ k32[1].B1] ^ k32[0].B1]
                        ^ MdsTable[2, P8x8[P_21, P8x8[P_22, x.B2] ^ k32[1].B2] ^ k32[0].B2]
                        ^ MdsTable[3, P8x8[P_31, P8x8[P_32, x.B3] ^ k32[1].B3] ^ k32[0].B3];

                return x;
            }


            private static DWord RotateLeft(DWord x, int n)
            {
                return (x << n) | (x >> (32 - n));
            }

            private static DWord RotateRight(DWord x, int n)
            {
                return (x >> n) | (x << (32 - n));
            }


            private static readonly uint P_01 = 0;
            private static readonly uint P_02 = 0;
            private static readonly uint P_03 = P_01 ^ 1; //"extend" to larger key sizes
            private static readonly uint P_04 = 1;

            private static readonly uint P_11 = 0;
            private static readonly uint P_12 = 1;
            private static readonly uint P_13 = P_11 ^ 1;
            private static readonly uint P_14 = 0;

            private static readonly uint P_21 = 1;
            private static readonly uint P_22 = 0;
            private static readonly uint P_23 = P_21 ^ 1;
            private static readonly uint P_24 = 0;

            private static readonly uint P_31 = 1;
            private static readonly uint P_32 = 1;
            private static readonly uint P_33 = P_31 ^ 1;
            private static readonly uint P_34 = 1;

            [SuppressMessage("Microsoft.Performance", "CA1814:PreferJaggedArraysOverMultidimensional",
                MessageId = "Member", Justification = "Multidimensional array does not waste space.")]
            private static readonly byte[,] P8x8 =
            {
                {
                    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
                    0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
                    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
                    0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
                    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
                    0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
                    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
                    0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
                    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
                    0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
                    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
                    0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
                    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
                    0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
                    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
                    0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
                    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
                    0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
                    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
                    0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
                    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
                    0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
                    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
                    0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
                    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
                    0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
                    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
                    0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
                    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
                    0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
                    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
                    0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
                },
                {
                    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
                    0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
                    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
                    0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
                    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
                    0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
                    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
                    0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
                    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
                    0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
                    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
                    0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
                    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
                    0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
                    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
                    0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
                    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
                    0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
                    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
                    0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
                    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
                    0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
                    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
                    0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
                    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
                    0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
                    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
                    0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
                    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
                    0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
                    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
                    0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
                }
            };

            [SuppressMessage("Microsoft.Performance", "CA1814:PreferJaggedArraysOverMultidimensional",
                MessageId = "Member", Justification = "Multidimensional array does not waste space.")]
            private static readonly DWord[,] MdsTable = new DWord[4, 256];

            private static bool MdsTableBuilt;
            private static readonly object BuildMdsSyncLock = new object();

            private static void BuildMds()
            {
                lock (BuildMdsSyncLock)
                {
                    if (MdsTableBuilt) return;

                    var m1 = new byte[2];
                    var mX = new byte[2];
                    var mY = new byte[4];

                    for (var i = 0; i < 256; i++)
                    {
                        m1[0] = P8x8[0, i]; /* compute all the matrix elements */
                        mX[0] = (byte) Mul_X(m1[0]);
                        mY[0] = (byte) Mul_Y(m1[0]);

                        m1[1] = P8x8[1, i];
                        mX[1] = (byte) Mul_X(m1[1]);
                        mY[1] = (byte) Mul_Y(m1[1]);

                        MdsTable[0, i].B0 = m1[1];
                        MdsTable[0, i].B1 = mX[1];
                        MdsTable[0, i].B2 = mY[1];
                        MdsTable[0, i].B3 = mY[1]; //SetMDS(0);

                        MdsTable[1, i].B0 = mY[0];
                        MdsTable[1, i].B1 = mY[0];
                        MdsTable[1, i].B2 = mX[0];
                        MdsTable[1, i].B3 = m1[0]; //SetMDS(1);

                        MdsTable[2, i].B0 = mX[1];
                        MdsTable[2, i].B1 = mY[1];
                        MdsTable[2, i].B2 = m1[1];
                        MdsTable[2, i].B3 = mY[1]; //SetMDS(2);

                        MdsTable[3, i].B0 = mX[0];
                        MdsTable[3, i].B1 = m1[0];
                        MdsTable[3, i].B2 = mY[0];
                        MdsTable[3, i].B3 = mX[0]; //SetMDS(3);
                    }

                    MdsTableBuilt = true;
                }
            }

            #endregion

            #region Reed-Solomon

            private const uint RS_GF_FDBK = 0x14D; //field generator

            /// <summary>
            ///     Use (12,8) Reed-Solomon code over GF(256) to produce a key S-box dword from two key material dwords.
            /// </summary>
            /// <param name="k0">1st dword</param>
            /// <param name="k1">2nd dword</param>
            private static DWord ReedSolomonMdsEncode(DWord k0, DWord k1)
            {
                var r = new DWord();
                for (var i = 0; i < 2; i++)
                {
                    r ^= i > 0 ? k0 : k1; //merge in 32 more key bits
                    for (var j = 0; j < 4; j++)
                    {
                        //shift one byte at a time 
                        var b = (byte) (r >> 24);
                        var g2 = (byte) ((b << 1) ^ ((b & 0x80) > 0 ? RS_GF_FDBK : 0));
                        var g3 = (byte) (((b >> 1) & 0x7F) ^ ((b & 1) > 0 ? RS_GF_FDBK >> 1 : 0) ^ g2);
                        r.B3 = (byte) (r.B2 ^ g3);
                        r.B2 = (byte) (r.B1 ^ g2);
                        r.B1 = (byte) (r.B0 ^ g3);
                        r.B0 = b;
                    }
                }
                return r;
            }


            private static uint Mul_X(uint x)
            {
                return Mx_X(x);
            }

            private static uint Mul_Y(uint x)
            {
                return Mx_Y(x);
            }


            private static uint Mx_X(uint x)
            {
                return x ^ LFSR2(x); //5B
            }

            private static uint Mx_Y(uint x)
            {
                return x ^ LFSR1(x) ^ LFSR2(x); //EF
            }


            private const uint MDS_GF_FDBK = 0x169; //primitive polynomial for GF(256)

            private static uint LFSR1(uint x)
            {
                return (x >> 1) ^ ((x & 0x01) > 0 ? MDS_GF_FDBK / 2 : 0);
            }

            private static uint LFSR2(uint x)
            {
                return (x >> 2) ^ ((x & 0x02) > 0 ? MDS_GF_FDBK / 2 : 0)
                       ^ ((x & 0x01) > 0 ? MDS_GF_FDBK / 4 : 0);
            }

            #endregion
        }
    }


    internal enum TwofishManagedTransformMode
    {
        Encrypt = 0,
        Decrypt = 1
    }
}