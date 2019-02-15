namespace Argon2_KDF
{
    //public class Argon2ArgumentFactory
    //{
        //static Argon2 ParseArguments(string[] args) {
        //    Options options = BuildOptions();

        //    CommandLineParser parser = new DefaultParser();
        //    HelpFormatter formatter = new HelpFormatter();
        //    CommandLine commandLine = null;

        //    try {
        //        commandLine = parser.parse(options, args);

        //        if (commandLine.getArgs().length != 1)
        //            throw new ParseException("no password or salt");

        //        return CreateArgon2(commandLine);
        //    }
        //    catch (ParseException e) {
        //        formatter.printHelp("argon2 salt", options, true);
        //        Console.WriteLine("Password is read from stdin");

        //        BailOut();
        //    }

        //    // not reachable
        //    return null;
        //}

        /// <summary>
        /// throws ParseException 
        /// </summary>
        /// <param name="commandLine"></param>
        /// <returns></returns>
        //private static Argon2 CreateArgon2(CommandLine commandLine) {
        //    Argon2 argon2 = new Argon2();
        //    string salt = commandLine.GetArgs()[0];

        //    argon2.SetSalt(salt);

        //    if (commandLine.HasOption("h"))
        //        throw new ParseException("usage");

        //    if (commandLine.HasOption("t")) {
        //        argon2.SetIterations(parseInt(commandLine.GetOptionValue("t")));
        //    }

        //    if (commandLine.hasOption("p")) {
        //        argon2.SetParallelism(parseInt(commandLine.getOptionValue("p")));
        //    }

        //    if (commandLine.hasOption("m")) {
        //        argon2.SetMemory(parseInt(commandLine.getOptionValue("m")));
        //    }
        //    else if (commandLine.hasOption("k")) {
        //        int k = parseInt(commandLine.getOptionValue("k"));
        //        if (k % 4 * argon2.GetLanes() != 0)
        //            throw new ParseException("k must be a multiple of p*4");
        //        argon2.SetMemoryInKiB(k);
        //    }


        //    if (commandLine.hasOption("e")) {
        //        argon2.SetEncodedOnly(true);
        //    }
        //    else if (commandLine.hasOption("r")) {
        //        argon2.SetRawOnly(true);
        //    }

        //    if (commandLine.hasOption("i")) {
        //        argon2.SetType(Argon2Type.Argon2i);
        //    }
        //    else if (commandLine.hasOption("d")) {
        //        argon2.SetType(Argon2Type.Argon2d);
        //    }
        //    else if (commandLine.hasOption("id")) {
        //        argon2.SetType(Argon2Type.Argon2id);
        //    }

        //    if (commandLine.hasOption(("l"))) {
        //        argon2.SetOutputLength(parseInt(commandLine.getOptionValue("l")));
        //    }

        //    if (commandLine.hasOption("v")) {
        //        int version = parseInt(commandLine.getOptionValue("v"));
        //        if (!(version == 10 || version == 13)) {
        //            BailOut("wrong version");
        //        }

        //        argon2.SetVersion(version);
        //    }

        //    return argon2;
        //}

        //private static Options BuildOptions() {
        //    Options options = new Options();
        //    Option option;

        //    OptionGroup optionGroup = new OptionGroup();

        //    option = new Option("i", null, false, "Use Argon2i (this is the default)");
        //    optionGroup.AddOption(option);
        //    option = new Option("d", null, false, "Use Argon2d instead of Argon2i");
        //    optionGroup.AddOption(option);
        //    option = new Option("id", null, false, "Use Argon2id instead of Argon2i");
        //    optionGroup.AddOption(option);

        //    options.AddOptionGroup(optionGroup);

        //    option = new Option("t", null, true, "Sets the number of iterations to N (default = 3)");
        //    option.SetArgName("N");
        //    option.SetType(Integer.class);
        //    options.AddOption(option);
        //    optionGroup = new OptionGroup();

        //option = new Option("m", null, true, "Sets the memory usage of 2^N KiB (default 12)");
        //option.SetArgName("N");
        //    option.SetType(Integer.class);
        //    optionGroup.AddOption(option);

        //    option = new Option("k", null, true, "Sets the memory usage of N KiB (default 2^12)");
        //option.SetArgName("N");
        //    option.SetType(Integer.class);
        //    optionGroup.AddOption(option);

        //    options.AddOptionGroup(optionGroup);

        //    option = new Option("p", null, true, "Sets parallelism to N (default 1)");
        //option.SetArgName("N");
        //    option.SetType(Integer.class);
        //    options.AddOption(option);

        //    option = new Option("l", null, true, "Sets hash output length to N bytes (default 32)");
        //option.SetArgName("N");
        //    option.SetType(Integer.class);
        //    options.AddOption(option);

        //    optionGroup = new OptionGroup();

        //option = new Option("e", null, false, "Output only encoded hash");
        //optionGroup.AddOption(option);
        //    option = new Option("r", null, false, "Output only the raw bytes of the hash");
        //optionGroup.AddOption(option);

        //    options.AddOptionGroup(optionGroup);

        //    option = new Option("h", null, false, "Print usage");
        //options.AddOption(option);

        //    return options;
        //}

        //private static void BailOut(string message) {
        //    Console.WriteLine((message);
        //    BailOut();
        //}

        //private static void BailOut() {
        //    System.Exit(1);
        //}
    //}
}
