using System;
using System.Diagnostics;

namespace Argon2_KDF
{
    public class Program
    {
        static void Main(string[] args) {
            Stopwatch stopwatch = Stopwatch.StartNew();
            //string hash1Value = Argon2Factory.Create().SetPassword("password".ToCharArray()).SetSalt("saltsalt").Hash();
            //stopwatch.Stop();
            //Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");
            //stopwatch.Reset();

            //stopwatch.Start();
            //string hash2Value = Argon2Factory.Create().SetVersion(Constants.ARGON2_VERSION_13)
            //    .SetPassword("password".ToCharArray()).SetSalt("saltsalt").Hash();
            //stopwatch.Stop();
            //Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");
            //stopwatch.Reset();

            //stopwatch.Start();
            //string hash3Value = Argon2Factory.Create().SetVersion(Constants.ARGON2_VERSION_13)
            //    .SetPassword("password".ToCharArray()).SetSalt("saltsalt").SetParallelism(4).Hash();
            //stopwatch.Stop();
            //Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");
            //stopwatch.Reset();

            //stopwatch.Start();
            //string hash4Value = Argon2Factory.Create().SetVersion(Constants.ARGON2_VERSION_13)
            //    .SetPassword("password".ToCharArray()).SetSalt("saltsalt").SetParallelism(1).SetMemory(2).Hash();
            //stopwatch.Stop();
            //Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");
            //stopwatch.Reset();

            //stopwatch.Start();
            //string hash5Value = Argon2Factory.Create().SetVersion(Constants.ARGON2_VERSION_13)
            //    .SetPassword("password".ToCharArray()).SetSalt("saltsalt").SetParallelism(4).SetMemory(4).SetOutputLength(256).Hash();
            //stopwatch.Stop();
            //Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");

            for (int i = 0; i < 10; i++) {
                stopwatch.Reset();
                stopwatch.Start();
                Console.WriteLine(Argon2Factory.Create().SetVersion(Constants.ARGON2_VERSION_13)
                    .SetPassword("password".ToCharArray()).SetSalt("TheQuickBrownFoxJumpsOverTheLazyDog").SetParallelism(2).SetMemory(4).SetOutputLength(256).Hash());
                stopwatch.Stop();
                Console.WriteLine($"Finished after {stopwatch.ElapsedMilliseconds}");
            }

            Console.ReadLine();
        }
    }
}
