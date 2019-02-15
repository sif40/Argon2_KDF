using Argon2_KDF.algorithm;
using Argon2_KDF.model;
using System;
using System.Diagnostics;
using System.Text;

namespace Argon2_KDF
{
    public class Argon2
    {
        private byte[] _output;
        private int _outputLength; // -l N
        private double _duration;

        private byte[] _password;
        private byte[] _salt;
        private byte[] _secret;
        private byte[] _additional;

        private int _iterations; // -t N
        private int _memory; // -m N
        private int _lanes; // -p N

        private int _version; // -v (10/13)
        private Argon2Type _type;

        private bool _clearMemory = true;
        private readonly Encoding _charset = new UTF8Encoding();

        private bool _encodedOnly = false;
        private bool _rawOnly = false;

        public Argon2() {
            _lanes = Constants.Defaults.LANES_DEF;
            _outputLength = Constants.Defaults.OUTLEN_DEF;
            _memory = 1 << Constants.Defaults.LOG_M_COST_DEF;
            _iterations = Constants.Defaults.T_COST_DEF;
            _version = Constants.Defaults.VERSION_DEF;
            _type = Constants.Defaults.TYPE_DEF;
        }

        private static byte[] ToByteArray(char[] chars, Encoding charset) {
            return charset.GetBytes(chars);
            //CharBuffer charBuffer = CharBuffer.wrap(chars);
            //ByteBuffer byteBuffer = _charset.encode(charBuffer);
            //byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
            //        byteBuffer.position(), byteBuffer.limit());
            //Array.Fill(byteBuffer.array(), (byte)0);
            //return bytes;
        }

        public string Hash(byte[] password, byte[] salt) {
            SetPassword(password);
            SetSalt(salt);

            return Hash();
        }

        public string Hash(char[] password, String salt) {
            SetPassword(password);
            SetSalt(salt);

            return Hash();
        }

        public string Hash() {
            try {
                Argon2Hash();
                return GetOutputString();
            }
            finally {
                Clear();
            }
        }

        private void Argon2Hash() {
            Validation.ValidateInput(this);

            //Stopwatch stopWatch = new Stopwatch();

            Instance instance = new Instance(this);
            Initializer.Initialize(instance, this);
            FillMemory.Fill(instance);
            Finalizer.Finalize(instance, this);

            //stopWatch.Stop();
            //_duration = stopWatch.Elapsed.Seconds;
        }

        public void Clear() {
            if (_password != null)
                Array.Fill<byte>(_password, 0, 0, _password.Length - 1);

            if (_salt != null)
                Array.Fill<byte>(_salt, 0, 0, _salt.Length - 1);

            if (_secret != null)
                Array.Fill<byte>(_secret, 0, 0, _secret.Length - 1);

            if (_additional != null)
                Array.Fill<byte>(_additional, 0, 0, _additional.Length - 1);
        }

        //public void PrintSummary() {
        //    if (_encodedOnly)
        //        Console.WriteLine(GetEncoded());
        //    else if (_rawOnly)
        //        Console.WriteLine(GetOutputString());
        //    else {
        //        Console.WriteLine("Type:\t\t" + _type);
        //        Console.WriteLine("Iterations:\t" + _iterations);
        //        Console.WriteLine("Memory:\t\t" + _memory + " KiB");
        //        Console.WriteLine("Parallelism:\t" + _lanes);
        //        Console.WriteLine("Hash:\t\t" + GetOutputString());
        //        Console.WriteLine("Encoded:\t " + GetEncoded());
        //        Console.WriteLine(_duration + " seconds");
        //    }
        //}

        public Argon2 SetMemoryInKiB(int memory) {
            _memory = memory;
            return this;
        }

        public Argon2 SetParallelism(int parallelism) {
            _lanes = parallelism;
            return this;
        }

        public Argon2 SetPassword(char[] password) => SetPassword(ToByteArray(password, _charset));

        public Argon2 SetSalt(string salt) => SetSalt(_charset.GetBytes(salt));

        public byte[] GetOutput() => _output;

        public void SetOutput(byte[] finalResult) => _output = finalResult;

        public string GetOutputString() => Util.BytesToHexString(_output);

        public int GetOutputLength() => _outputLength;

        public Argon2 SetOutputLength(int outputLength) {
            _outputLength = outputLength;
            return this;
        }

        public byte[] GetPassword() => _password;

        public Argon2 SetPassword(byte[] password) {
            _password = password;
            return this;
        }

        public int GetPasswordLength() => _password.Length;

        public byte[] GetSalt() => _salt;

        public Argon2 SetSalt(byte[] salt) {
            _salt = salt;
            return this;
        }

        public int GetSaltLength() => _salt.Length;

        public byte[] GetSecret() => _secret;

        public Argon2 SetSecret(byte[] secret) {
            _secret = secret;
            return this;
        }

        public int GetSecretLength() => _secret?.Length ?? 0;

        public byte[] GetAdditional() => _additional;

        public Argon2 SetAdditional(byte[] additional) {
            _additional = additional;
            return this;
        }

        public int GetAdditionalLength() => _additional?.Length ?? 0;

        public int GetIterations() => _iterations;

        public Argon2 SetIterations(int iterations) {
            _iterations = iterations;
            return this;
        }

        public int GetMemory() => _memory;

        public Argon2 SetMemory(int memory) {
            _memory = 1 << memory;
            return this;
        }

        public int GetLanes() => _lanes;

        public int GetVersion() => _version;

        public Argon2 SetVersion(int version) {
            _version = version;
            return this;
        }

        public new Argon2Type GetType() => _type;

        public Argon2 SetType(Argon2Type type) {
            _type = type;
            return this;
        }

        public bool IsClearMemory() => _clearMemory;

        public void SetClearMemory(bool clearMemory) => _clearMemory = clearMemory;

        public Encoding GetCharset() => _charset;

        public void SetEncodedOnly(bool encodedOnly) => _encodedOnly = encodedOnly;

        public void SetRawOnly(bool rawOnly) => _rawOnly = rawOnly;

        public string GetEncoded() => "";
    }
}
