using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class VariableDeclaratorSyntaxResult
    {
        public bool IsVariableDeclaratorSyntaxPresent { get; set; }
        public VariableDeclaratorSyntax VariableDeclaratorSyntaxNode { get; set; }
        public ISymbol VariableDeclaratorSymbolInfo { get; set; }
    }
}
