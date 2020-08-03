using System;

namespace AliasAnalysisTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string secret = "This is a secret message";
            string secretAlias = secret;

            GetValues getValues = new GetValues();
            string taintedText = getValues.foo(secretAlias);

            Console.WriteLine($"Tainted Text is {taintedText}");
        }
    }
}
