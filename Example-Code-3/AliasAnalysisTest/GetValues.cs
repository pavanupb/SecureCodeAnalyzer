using System;
using System.Collections.Generic;
using System.Text;

namespace AliasAnalysisTest
{
    public class GetValues
    {
        public byte[] foo(byte[] recievedText)
        {
            byte[] recievedAliasedText = recievedText;
            return recievedAliasedText;
        }
    }
}
