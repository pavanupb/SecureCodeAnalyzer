using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class StringLiteralExpressionResult
    {
        public AssignmentExpressionSyntax ExpressionSyntax { get; set; }
        public bool IsStringLiteralInitializer { get; set; }
    }
}
