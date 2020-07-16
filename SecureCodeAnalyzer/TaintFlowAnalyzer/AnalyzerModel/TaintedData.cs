using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class TaintedData
    {
        public ISymbol NodeSymbol { get; set; }

        public ISymbol MyProperty { get; set; }
    }
}
