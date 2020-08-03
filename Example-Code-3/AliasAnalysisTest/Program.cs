using System;

namespace AliasAnalysisTest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            DemoClass demoClass = new DemoClass();
            demoClass.ByteValue = secret;

            //byte[] secretAlias = demoClass.ByteValue;

            GetValues getValues = new GetValues();
            byte[] taintedText = getValues.foo(demoClass.ByteValue);

            Console.WriteLine($"Tainted Text is {taintedText}");
        }
    }
}
