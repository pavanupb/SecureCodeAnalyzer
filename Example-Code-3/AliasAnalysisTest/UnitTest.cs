using System;
using System.Collections.Generic;
using System.Text;

namespace AliasAnalysisTest
{
    public class UnitTest
    {
        [Fact]
        public void TestTypeToTrack_HazardousIfStringIsNonNull_StringEmpty_Flagged()
        {
            VerifyCSharp(@"
using System;

class Program
    {
        static void Main(string[] args)
        {
            byte[] secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

            DemoClass demoClass = new DemoClass();
            demoClass.ByteValue = secret;           

            GetValues getValues = new GetValues();
            byte[] taintedText = getValues.foo(demoClass.ByteValue);            
        }
    }
public class GetValues
    {
        public byte[] foo(byte[] recievedText)
        {
            byte[] recievedAliasedText = recievedText;
            return recievedAliasedText;
        }
    }",
                TestTypeToTrack_HazardousIfStringIsNonNull,                
                (11, 9, "byte[] GetValues.foo(DemoClass ByteValue)", HazardousUsageEvaluationResult.Flagged));
                // recievedAliasedText should be present in the points-to set of DemoClass.ByteValue.
                (17, 9, "DemoClass ByteValue", HazardousUsageEvaluationResult.Flagged));
                // recievedAliasedText should be present in the points-to set of DemoClass.ByteValue.
                (12, 9, "DemoClass ByteValue", HazardousUsageEvaluationResult.Flagged));

        }

    }
}
