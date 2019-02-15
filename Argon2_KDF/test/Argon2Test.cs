using System;
using Argon2_KDF.algorithm;
using Argon2_KDF.model;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Argon2_KDF.test
{
    //[TestClass]
    //public class Argon2Test
    //{
    //    private string instanceNull = "0011a4db4b4dc5422bfab9973caf41bd78d9b20f9a01c236e329c65ffa67c2e6d655eada0eddbc82fe29d0a8fc33ca267e76889ac563e5fcf2a61cb395bd32404a9f9f6bed4324328e4671614efd85ebaa3ff319a4b5996c3fb04e85188839580c945aa12081d3496c6f9a25bf3214d0f766e54c372361a0f3d62ad7acc5cb0306b8fca890e0fcdf932597e3f819ff1ae836976dae0af12b8d53036d1cff4b3bbf5a25de57828ed2de7baa364f0b32ff3ce0626c7cb1e3b76d9bf9a7857e051c1c7a3368792fa1a01a79a7b6c83f97a2cfb3c40c9a7c5f3616673f1f97716a10c6e27a950fb737aab6c544ab59bff3f328a13acf432942c0096420ac7a1ed2de34c181aaf71802ed9a56184476b983e011a50a6203f628d9028d1b442c006d95cbe819acc754451862eab50d7df1ec6ac6bcd55169a7c64f00a3305609df52a178498c44e1d11adf56661e600eeeaf5132864fb99e937cfd3173141e3e619451f1b774719fe6c9d16a73edad3fd494e7520cdefe9e77e210ae2bff00d398e91d6a387775e0a6d9806dc88fa4c481bf4968565cd82df21d135d3bba1cb64c6b65a99d56dd55143f6658d99a5e2c6768394a1036e9cf32fdbaaf704a28d6671423ceb5b54074eb0bde342d541b597a27bf6eced39c168f47da2650df61f96280c1c0f3b858d51534061180c7185ff5f0293a76be3a165ad547303c81c7a480e9eaeddf7f5770b90c3600535b1b3f4be981c357fe08f8db0405ff7d4bc7e5fa94653038aa72ea2f4d4bbb6eb7e5ac76166c57151f0f9c1d26e0307e0d037119e647d33399e8bd0a66b60d18bd0e53af50658e8288b3e829365743abb199c5c59cc910756eb6eacd2a1d73646e47215998d96458be9b00ebf04fc46cdd651d02339822400b5a9565ba11e4b368fbcbdc6ee047ef6e93e66fc08aa0b24349f929d6d3122f2b96b683d709a9c18f584914df5397cf106076fe63823c63470b4c641a7057cf6a690956b6c03db91133db7620cb5e929204a0771c17ac3edb4778e95cb41173c91db45740e1023493242b684cefa0544e384adc8913c4e7bd4711088c2b87d1b922c59bed69a5afbc241cc270268eab791969e3d4181199295af1562631cc5147f8e17607620d965509623ff65261319f2084fb670e473fa990f2b52a6a3fe9dd9b4630e124d7c1b21df4fe4db64b53d4e8c1be5f50093d271a2a7818518ecb786f3c5d36555d348eb3f26fe7031d491167f1c8cd1974e75eb3a205949b3f8b4be0d7dffdee49069f6fa23bd8dec2d950aad3bacae2d3208d543171868665f9d1d6837dab20672d25a32b6794cfc1492a8cf06dcc142a9ca91dc81f00d20038fd7e26e0af42e2a4727a3b4f7b49a17cf3f660635a18063773e3999c3bda22e749b4cb7da41c455ac3e261d64e992d58e28f8157687c5ace8d26349544b3";
    //    private Argon2 argon2;

    //    [TestMethod]
    //    public void BasicTest() {
    //        argon2 = Argon2Factory.Create().SetPassword("password".ToCharArray()).SetSalt("saltsalt");
    //        Instance instance = new Instance(argon2);
    //        Initializer.Initialize(instance, argon2);

    //        Assert.Equals(instanceNull, instance.GetMemory()[0].ToString());
    //    }

    //    [TestMethod]
    //    public void HashTest() {

    //        bool largeRam = false;

    //        int version = Constants.ARGON2_VERSION_10;
    //        Console.WriteLine("Test Argon2i version number: " + version);
    //        /* Multiple test cases for various input values */
    //        HashTest(version, 2, 16, 1, "password", "somesalt",
    //                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
    //                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
    //                        "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", Constants.Defaults.OUTLEN_DEF);
    //        if (largeRam) {

    //            HashTest(version, 2, 20, 1, "password", "somesalt",
    //                    "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
    //                    "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ" +
    //                            "$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk", Constants.Defaults.OUTLEN_DEF);

    //            HashTest(version, 2, 18, 1, "password", "somesalt",
    //                    "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
    //                    "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ" +
    //                            "$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc", Constants.Defaults.OUTLEN_DEF);
    //        }

    //        HashTest(version, 2, 8, 1, "password", "somesalt",
    //                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
    //                "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ" +
    //                        "$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 8, 2, "password", "somesalt",
    //                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
    //                "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ" +
    //                        "$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 1, 16, 1, "password", "somesalt",
    //                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
    //                "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ" +
    //                        "$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 4, 16, 1, "password", "somesalt",
    //                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
    //                "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ" +
    //                        "$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 16, 1, "differentpassword", "somesalt",
    //                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
    //                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" +
    //                        "$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 16, 1, "password", "diffsalt",
    //                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
    //                "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
    //                        "$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 16, 1, "password", "diffsalt",
    //                "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccefc6ec9789f30a6b5a034591f51af830f4",
    //                "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
    //                        "$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc", 112);


    //        version = Constants.Defaults.ARGON2_VERSION_NUMBER;
    //        Console.WriteLine("Test Argon2i version number: " + version);

    //        /* Multiple test cases for various input values */
    //        HashTest(version, 2, 16, 1, "password", "somesalt",
    //                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
    //                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
    //                        "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", Constants.Defaults.OUTLEN_DEF);
    //        if (largeRam) {
    //            HashTest(version, 2, 20, 1, "password", "somesalt",
    //                    "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
    //                    "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ" +
    //                            "$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E", Constants.Defaults.OUTLEN_DEF);

    //            HashTest(version, 2, 18, 1, "password", "somesalt",
    //                    "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
    //                    "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ" +
    //                            "$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s", Constants.Defaults.OUTLEN_DEF);
    //        }

    //        HashTest(version, 2, 8, 1, "password", "somesalt",
    //                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
    //                "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ" +
    //                        "$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 8, 2, "password", "somesalt",
    //                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
    //                "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ" +
    //                        "$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 1, 16, 1, "password", "somesalt",
    //                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
    //                "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ" +
    //                        "$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 4, 16, 1, "password", "somesalt",
    //                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
    //                "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ" +
    //                        "$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 16, 1, "differentpassword", "somesalt",
    //                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
    //                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" +
    //                        "$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4", Constants.Defaults.OUTLEN_DEF);

    //        HashTest(version, 2, 16, 1, "password", "diffsalt",
    //                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
    //                "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ" +
    //                        "$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE", Constants.Defaults.OUTLEN_DEF);
    //    }

    //    private void HashTest(int version, int iterations, 
    //                          int memory, int parallelism,
    //                          string password, string salt, 
    //                          string passwordRef, string mcfref, int outputLength) {

    //        string result = Argon2Factory.Create()
    //            .SetVersion(version)
    //            .SetIterations(iterations)
    //            .SetMemory(memory)
    //            .SetParallelism(parallelism)
    //            .SetOutputLength(outputLength)
    //            .Hash(password.ToCharArray(), salt);

    //        Assert.Equals(passwordRef, result);
    //        //if (!result.Equals(passwordRef)) {
    //        //    fail();
    //        //}
    //    }
    //}
}
