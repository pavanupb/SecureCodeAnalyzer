using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class ContextInformation
    {
        public ISymbol ContainingSymbolInfo { get; set; }
        public ISymbol ContainingObjectSymbolInfo { get; set; }
        public ISymbol CallerSymbolInfo { get; set; }
    }
}
