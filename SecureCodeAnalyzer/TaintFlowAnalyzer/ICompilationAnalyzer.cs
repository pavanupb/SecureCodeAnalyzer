using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Text;

namespace TaintFlowAnalyzer
{
    public interface ICompilationAnalyzer
    {
        void AnalyzeCodeBlockStartAction(CodeBlockStartAnalysisContext<SyntaxKind> context);
        void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context);
        void AnalyzeMethodInvocationNode(SyntaxNodeAnalysisContext context);
        void AnalyzeSimpleAssignmentExpression(SyntaxNodeAnalysisContext context);
        void AnalyzeLocalDeclarationStatement(SyntaxNodeAnalysisContext context);
        void AnalyzeExpressionStatement(SyntaxNodeAnalysisContext context);
        void AnalyzeCodeBlockEndAction(CodeBlockAnalysisContext context);
        void AnalyzeCompilationEndAction(CompilationAnalysisContext context);
    }
}
