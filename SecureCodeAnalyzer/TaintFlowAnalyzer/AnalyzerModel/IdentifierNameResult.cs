using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class IdentifierNameResult
    {
        public bool IsIdentifierNodePresent { get; set; }
        public IdentifierNameSyntax IdentifierNameSyntax { get; set; }
    }
}
