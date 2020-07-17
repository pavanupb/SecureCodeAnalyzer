using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CodeSharpenerCryptoAnalyzer.AnalyzerModels;
using CodeSharpenerCryptoAnalyzer.Visitors;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TaintFlowAnalyzer;

namespace SecureCodeAnalyzer
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class SecureCodeAnalyzerAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SecureCodeAnalyzer";

        public const string HardCodedCheckDiagnosticId = "HardCodedKey";
        private static readonly LocalizableString HardCodedCheckTitle = new LocalizableResourceString(nameof(Resources.HardCodedKeysTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString HardCodedCheckMessageFormat = new LocalizableResourceString(nameof(Resources.HardCodedMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString HardCodedCheckDescription = new LocalizableResourceString(nameof(Resources.HardCodedDescription), Resources.ResourceManager, typeof(Resources));
        private const string HardCodedCheckCategory = "Violation";
        private static DiagnosticDescriptor HardCodedCheckViolationRule = new DiagnosticDescriptor(HardCodedCheckDiagnosticId, HardCodedCheckTitle, HardCodedCheckMessageFormat, HardCodedCheckCategory, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: HardCodedCheckDescription);

        public const string HardCodedContextCheckDiagnosticId = "HardCodedContextKey";
        private static readonly LocalizableString HardCodedContextCheckTitle = new LocalizableResourceString(nameof(Resources.HardCodedContextTitle), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString HardCodedContextCheckMessageFormat = new LocalizableResourceString(nameof(Resources.HardCodedContextMessageFormat), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString HardCodedContextCheckDescription = new LocalizableResourceString(nameof(Resources.HardCodedContextDescription), Resources.ResourceManager, typeof(Resources));
        private const string HardCodedContextCheckCategory = "Violation";
        private static DiagnosticDescriptor HardCodedContextCheckViolationRule = new DiagnosticDescriptor(HardCodedContextCheckDiagnosticId, HardCodedContextCheckTitle, HardCodedContextCheckMessageFormat, HardCodedContextCheckCategory, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: HardCodedContextCheckDescription);        

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(HardCodedCheckViolationRule, HardCodedContextCheckViolationRule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.RegisterCompilationStartAction(compilationContext =>
            {
                CompilationAnalyzer cryptoAnalyzer = new CompilationAnalyzer(HardCodedCheckViolationRule, HardCodedContextCheckViolationRule);
                compilationContext.RegisterCodeBlockStartAction<SyntaxKind>(cryptoAnalyzer.AnalyzeCodeBlockStartAction);
                compilationContext.RegisterCompilationEndAction(cryptoAnalyzer.AnalyzeCompilationEndAction);

            });       
        }
    }
}
