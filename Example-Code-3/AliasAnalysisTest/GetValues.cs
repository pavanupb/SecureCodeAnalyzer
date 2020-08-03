using System;
using System.Collections.Generic;
using System.Text;

namespace AliasAnalysisTest
{
    public class GetValues
    {
        public string foo(string recievedText)
        {
            string recievedAliasedText = recievedText;
            return recievedAliasedText;
        }
    }
}
