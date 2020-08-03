using Analyzer.Utilities;
using CodeSharpenerCryptoAnalyzer.AnalyzerModels;
using CodeSharpenerCryptoAnalyzer.Visitors;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.CopyAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;


namespace TaintFlowAnalyzer
{
    public class CompilationAnalyzer : ICompilationAnalyzer
    {        
        private static DiagnosticDescriptor HardCodedCheckViolationRule;
        private static DiagnosticDescriptor HardCodedContextCheckViolationRule;
        private List<KeyValuePair<ContextInformation, ISymbol>> TaintedValuesDictionary;
        private ConcurrentDictionary<string, List<KeyValuePair<ContextInformation, ISymbol>>> TaintedContextDictionary;
        private readonly HashSet<Diagnostic> _diagnostics = new HashSet<Diagnostic>();
        private readonly ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics;



        public CompilationAnalyzer(DiagnosticDescriptor hardCodedRule, DiagnosticDescriptor hardCodedContextRule, ImmutableArray<DiagnosticDescriptor> supportedDiagnostics)
        {            
            HardCodedCheckViolationRule = hardCodedRule;
            HardCodedContextCheckViolationRule = hardCodedContextRule;
            if (TaintedContextDictionary == null)
            {
                TaintedContextDictionary = new ConcurrentDictionary<string, List<KeyValuePair<ContextInformation, ISymbol>>>();
            }

            SupportedDiagnostics = supportedDiagnostics;

            /*if (TaintedValuesDictionary == null)
            {
                TaintedValuesDictionary = new List<KeyValuePair<ContextInformation, ISymbol>>();
            }*/
        } 

        public void AnalyzeCodeBlockStartAction(CodeBlockStartAnalysisContext<SyntaxKind> context)
        {            

            TaintedValuesDictionary = new List<KeyValuePair<ContextInformation, ISymbol>>();
            List<KeyValuePair<ContextInformation, ISymbol>> taintedDictionary = new List<KeyValuePair<ContextInformation, ISymbol>>();
            lock (TaintedContextDictionary)
            {
                TaintedContextDictionary.TryGetValue(context.OwningSymbol.ToString(), out taintedDictionary);
            }
            if (taintedDictionary != null)
            {
                lock (TaintedContextDictionary)
                {
                    List<KeyValuePair<ContextInformation, ISymbol>> removedValue;
                    TaintedContextDictionary.TryRemove(context.OwningSymbol.ToString(), out removedValue);
                }
            }

            foreach (var taintedContextDictionary in TaintedContextDictionary)
            {
                foreach (var taintedValueDictionary in taintedContextDictionary.Value)
                {
                    if (taintedValueDictionary.Key.ContainingSymbolInfo != null)
                    {
                        if (taintedValueDictionary.Key.ContainingSymbolInfo.ToString().Equals(context.OwningSymbol.ToString()))
                        {
                            lock (TaintedValuesDictionary)
                            {
                                TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(taintedValueDictionary.Key, taintedValueDictionary.Value));
                            }
                        }
                    }
                }
            }


            var controlFlowGraph = ControlFlowGraph.Create(context.CodeBlock, context.SemanticModel);
            WellKnownTypeProvider wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(context.SemanticModel.Compilation);
            InterproceduralAnalysisConfiguration interproceduralAnalysisConfiguration = InterproceduralAnalysisConfiguration.Create(
                                                                    context.Options,
                                                                    SupportedDiagnostics,
                                                                    context.OwningSymbol,
                                                                    context.SemanticModel.Compilation,
                                                                    defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                                    cancellationToken: context.CancellationToken);


                      

            var pointsToResult = PointsToAnalysis.TryGetOrComputeResult(controlFlowGraph,
                context.OwningSymbol,
                context.Options,
                wellKnownTypeProvider,
                interproceduralAnalysisConfig: interproceduralAnalysisConfiguration,
                interproceduralAnalysisPredicateOpt: null
               );

            var copyAnalysis = CopyAnalysis.TryGetOrComputeResult(controlFlowGraph,
                context.OwningSymbol,
                context.Options,
                wellKnownTypeProvider,
                interproceduralAnalysisConfiguration,
                interproceduralAnalysisPredicateOpt: null
                );

            var exitBlockAliasInfo = copyAnalysis.ExitBlockOutput.Data.Select(x => x).Where(y => y.Value.Kind.Equals(CopyAbstractValueKind.KnownReferenceCopy));
            var mergeBlockAliasInfo = copyAnalysis.MergedStateForUnhandledThrowOperationsOpt.Data.Select(x => x).Where(y => y.Value.Kind.Equals(CopyAbstractValueKind.KnownReferenceCopy));

            var exitBlockInfo = copyAnalysis.ExitBlockOutput.Data.Select(x => x).Where(y => y.Key.SymbolOpt != null).Select(z => z.Key.SymbolOpt.Name.Equals("aesAlg"));
            var mergeBlockInfo = copyAnalysis.MergedStateForUnhandledThrowOperationsOpt.Data.Select(x => x).Where(y => y.Key.SymbolOpt != null && y.Key.SymbolOpt.Name.Equals("aesAlg"));




            //All the syntax node action goes here
            context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
            context.RegisterSyntaxNodeAction(AnalyzeMethodInvocationNode, SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(AnalyzeSimpleAssignmentExpression, SyntaxKind.SimpleAssignmentExpression);
            context.RegisterSyntaxNodeAction(AnalyzeLocalDeclarationStatement, SyntaxKind.LocalDeclarationStatement, SyntaxKind.FieldDeclaration);
            context.RegisterSyntaxNodeAction(AnalyzeExpressionStatement, SyntaxKind.ExpressionStatement);

            context.RegisterCodeBlockEndAction(AnalyzeCodeBlockEndAction);
        }

        public void AnalyzeCodeBlockEndAction(CodeBlockAnalysisContext context)
        {
            List<KeyValuePair<ContextInformation, ISymbol>> taintedDict = new List<KeyValuePair<ContextInformation, ISymbol>>();
            lock (TaintedContextDictionary)
            {
                TaintedContextDictionary.TryGetValue(context.OwningSymbol.ToString(), out taintedDict);
            }
            if (taintedDict == null)
            {
                lock (TaintedContextDictionary)
                {
                    TaintedContextDictionary.TryAdd(context.OwningSymbol.ToString(), TaintedValuesDictionary.ToList());
                }
            }
            //Clear the Tainted Values Dictionary
            lock (TaintedValuesDictionary)
            {
                TaintedValuesDictionary.Clear();
            }            
        }

        public void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
        {
            var objectCreationNode = context.Node;
            var identifierNode = objectCreationNode.ChildNodes().OfType<IdentifierNameSyntax>();
            var argumentsList = objectCreationNode.ChildNodes().OfType<ArgumentListSyntax>();
            var objectSymbolInfo = context.SemanticModel.GetSymbolInfo(objectCreationNode).Symbol;

            if (objectSymbolInfo != null)
            {
                //Check only for string instances
                if (objectSymbolInfo.ContainingSymbol.ToString().Equals("System.String") || objectSymbolInfo.ContainingSymbol.ToString().Equals("System.Text.StringBuilder"))
                {
                    //Check for tainted string arguments
                    foreach (var argumentListSyntax in argumentsList)
                    {
                        var argumentSyntaxList = argumentListSyntax.Arguments;
                        if (argumentSyntaxList != null)
                        {
                            foreach (var arguments in argumentSyntaxList)
                            {
                                var identifierArgumentNode = arguments.ChildNodes().OfType<IdentifierNameSyntax>();
                                if (identifierArgumentNode.Count() != 0)
                                {
                                    var identifierSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierArgumentNode.FirstOrDefault()).Symbol;
                                    if (identifierSymbolInfo != null)
                                    {
                                        var taintedIdentifierSymbolInfo = IsTaintedValueExists(identifierSymbolInfo.ContainingSymbol, identifierSymbolInfo);
                                        if (taintedIdentifierSymbolInfo.IsTainted)
                                        {
                                            var declaratorSyntaxNode = objectCreationNode.AncestorsAndSelf().OfType<VariableDeclaratorSyntax>();
                                            if (declaratorSyntaxNode.Count() != 0)
                                            {
                                                var declaratorSymbolInfo = context.SemanticModel.GetDeclaredSymbol(declaratorSyntaxNode.FirstOrDefault());
                                                var taintedDeclaratorSymbolInfo = IsTaintedValueExists(declaratorSymbolInfo.ContainingSymbol, declaratorSymbolInfo);
                                                if (!taintedDeclaratorSymbolInfo.IsTainted)
                                                {
                                                    lock (TaintedValuesDictionary)
                                                    {
                                                        ContextInformation contextInformation = new ContextInformation
                                                        {
                                                            ContainingSymbolInfo = declaratorSymbolInfo.ContainingSymbol
                                                        };
                                                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, declaratorSymbolInfo));
                                                    }
                                                }
                                            }                                            
                                            ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, arguments.GetLocation(), taintedIdentifierSymbolInfo.TaintedContextInformation);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //Check if any argument value is tainted                                
            foreach (var argumentList in argumentsList)
            {
                if (argumentList.Arguments != null)
                {
                    foreach (var arguments in argumentList.Arguments)
                    {
                        ArgumentsVisitor argumentsVisitor = new ArgumentsVisitor();
                        argumentsVisitor.Visit(arguments);
                        var isIdentifierPresent = argumentsVisitor.GetResult();
                        if (isIdentifierPresent.IsIdentifierNodePresent)
                        {
                            var argumentSymbolInfo = context.SemanticModel.GetSymbolInfo(isIdentifierPresent.IdentifierNameSyntax);
                            if (argumentSymbolInfo.Symbol != null)
                            {
                                var taintedArgumentSymbolInfo = IsTaintedValueExists(argumentSymbolInfo.Symbol.ContainingSymbol, argumentSymbolInfo.Symbol);
                                if (taintedArgumentSymbolInfo.IsTainted)
                                {
                                    ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, arguments.GetLocation(), taintedArgumentSymbolInfo.TaintedContextInformation);
                                }
                            }
                        }
                    }
                }
            }
        }

        public void AnalyzeMethodInvocationNode(SyntaxNodeAnalysisContext context)
        {
            var diagnostics = context.Compilation.GetDiagnostics();
            var invocationExpressionNode = context.Node;
            var memAcessExprNode = invocationExpressionNode.ChildNodes().OfType<MemberAccessExpressionSyntax>();
            var argumentsList = invocationExpressionNode.ChildNodes().OfType<ArgumentListSyntax>();

            foreach (var node in memAcessExprNode)
            {
                var identifierNode = node.ChildNodes().OfType<IdentifierNameSyntax>();

                if (identifierNode.Count() > 0)
                {
                    var declaratorNode = identifierNode.FirstOrDefault().AncestorsAndSelf().OfType<VariableDeclaratorSyntax>();
                    ISymbol declaratorSymbolInfo = null;
                    if (declaratorNode.Count() != 0)
                    {
                        declaratorSymbolInfo = context.SemanticModel.GetDeclaredSymbol(declaratorNode.FirstOrDefault());
                    }

                    //Check for any tainted invocations
                    var invocatorIdentifierSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierNode.FirstOrDefault()).Symbol;
                    if (invocatorIdentifierSymbolInfo != null)
                    {
                        var taintedInvocatorIdentifierSymbolInfo = IsTaintedValueExists(invocatorIdentifierSymbolInfo.ContainingSymbol, invocatorIdentifierSymbolInfo);
                        if (taintedInvocatorIdentifierSymbolInfo.IsTainted)
                        {
                            if (!taintedInvocatorIdentifierSymbolInfo.IsTainted)
                            {
                                lock (TaintedValuesDictionary)
                                {
                                    ContextInformation contextInformation = new ContextInformation
                                    {
                                        ContainingSymbolInfo = invocatorIdentifierSymbolInfo.ContainingSymbol
                                    };
                                    TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, invocatorIdentifierSymbolInfo));
                                }
                            }
                            if (declaratorSymbolInfo != null)
                            {
                                var taintedDeclaratorSymbolInfo = IsTaintedValueExists(declaratorSymbolInfo.ContainingSymbol, declaratorSymbolInfo);
                                if (!taintedDeclaratorSymbolInfo.IsTainted)
                                {
                                    lock (TaintedValuesDictionary)
                                    {
                                        ContextInformation contextInformation = new ContextInformation
                                        {
                                            CallerSymbolInfo = context.ContainingSymbol
                                        };
                                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, declaratorSymbolInfo));
                                    }
                                }
                            }
                            ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, node.GetLocation(), taintedInvocatorIdentifierSymbolInfo.TaintedContextInformation);
                        }
                    }
                }
            }
            //Check for callee's tainted value
            var invExprSymbolInfo = context.SemanticModel.GetSymbolInfo(invocationExpressionNode).Symbol as IMethodSymbol;
            foreach (var arguments in argumentsList)
            {
                for (int i = 0; i < arguments.Arguments.Count; i++)
                {
                    var simpleMemAccessExpr = arguments.Arguments[i].ChildNodes().OfType<MemberAccessExpressionSyntax>();
                    //Callee's tainted value containing simple access expressions
                    if (simpleMemAccessExpr.Count() > 0)
                    {
                        foreach (var memAccessExpr in simpleMemAccessExpr)
                        {
                            var argumentSymbol = context.SemanticModel.GetSymbolInfo(memAccessExpr).Symbol;
                            if (argumentSymbol != null)
                            {
                                var taintedArgumentSymbolInfo = IsTaintedValueExists(argumentSymbol.ContainingSymbol, argumentSymbol);
                                if (taintedArgumentSymbolInfo.IsTainted)
                                {
                                    ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, memAccessExpr.GetLocation(), taintedArgumentSymbolInfo.TaintedContextInformation);
                                    /*var diagnsotics = (taintedArgumentSymbolInfo.TaintedContextInformation.CallerSymbolInfo != null) ? Diagnostic.Create(HardCodedContextCheckViolationRule, memAccessExpr.GetLocation(), taintedArgumentSymbolInfo.TaintedContextInformation.CallerSymbolInfo.ToString()) : Diagnostic.Create(HardCodedCheckViolationRule, memAccessExpr.GetLocation());
                                    context.ReportDiagnostic(diagnsotics);*/
                                    if (invExprSymbolInfo != null)
                                    {
                                        var taintedInvExprSymbolInfo = IsTaintedValueExists(invExprSymbolInfo, invExprSymbolInfo.Parameters[i]);
                                        if (!taintedInvExprSymbolInfo.IsTainted)
                                        {
                                            lock (TaintedValuesDictionary)
                                            {
                                                ContextInformation contextInformation = new ContextInformation
                                                {
                                                    ContainingSymbolInfo = invExprSymbolInfo,
                                                    CallerSymbolInfo = context.ContainingSymbol
                                                };
                                                TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, invExprSymbolInfo.Parameters[i]));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    //callee's tainted value containing identifer symbols
                    else
                    {
                        var identifierNameSyntax = arguments.Arguments[i].ChildNodes().OfType<IdentifierNameSyntax>();
                        foreach (var identifierNameNode in identifierNameSyntax)
                        {
                            var identifierSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierNameNode).Symbol;
                            if (identifierSymbolInfo != null)
                            {
                                var taintedIdentifierSymbolInfo = IsTaintedValueExists(identifierSymbolInfo.ContainingSymbol, identifierSymbolInfo);
                                if (taintedIdentifierSymbolInfo.IsTainted)
                                {
                                    var variableDeclaratorResult = GetVariableDeclarator(invocationExpressionNode, context);
                                    // Taint Variable Declarator only for methods containing inside "System" namespace and not for any user defined methods.
                                    if (invExprSymbolInfo != null)
                                    {
                                        if (variableDeclaratorResult.IsVariableDeclaratorSyntaxPresent && invExprSymbolInfo.Name.Equals("FromBase64String"))
                                        {
                                            var diagnsotics = Diagnostic.Create(HardCodedCheckViolationRule, variableDeclaratorResult.VariableDeclaratorSyntaxNode.GetLocation());
                                            lock(_diagnostics)
                                            {
                                                _diagnostics.Add(diagnsotics);
                                            }
                                            //context.ReportDiagnostic(diagnsotics);
                                            var taintedVariableDeclaratorResult = IsTaintedValueExists(variableDeclaratorResult.VariableDeclaratorSymbolInfo.ContainingSymbol, variableDeclaratorResult.VariableDeclaratorSymbolInfo);
                                            if (!taintedVariableDeclaratorResult.IsTainted)
                                            {
                                                lock (TaintedValuesDictionary)
                                                {
                                                    ContextInformation contextInformation = new ContextInformation
                                                    {
                                                        ContainingSymbolInfo = variableDeclaratorResult.VariableDeclaratorSymbolInfo.ContainingSymbol,
                                                    };
                                                    TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, variableDeclaratorResult.VariableDeclaratorSymbolInfo));
                                                }
                                            }
                                        }
                                        else
                                        {
                                            ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, identifierNameNode.GetLocation(), taintedIdentifierSymbolInfo.TaintedContextInformation);
                                            /*var diagnsotics = (taintedIdentifierSymbolInfo.TaintedContextInformation.CallerSymbolInfo != null) ? Diagnostic.Create(HardCodedContextCheckViolationRule, identifierNameNode.GetLocation(), taintedIdentifierSymbolInfo.TaintedContextInformation.CallerSymbolInfo.ToString()) : Diagnostic.Create(HardCodedCheckViolationRule, identifierNameNode.GetLocation());
                                            context.ReportDiagnostic(diagnsotics);*/
                                        }
                                    }
                                    //Condition to check callee's tainted symbol info.
                                    if (invExprSymbolInfo != null)
                                    {
                                        var taintedInvExprSymbolInfo = IsTaintedValueExists(invExprSymbolInfo, invExprSymbolInfo.Parameters[i]);
                                        if (!taintedInvExprSymbolInfo.IsTainted)
                                        {
                                            lock (TaintedValuesDictionary)
                                            {
                                                ContextInformation contextInformation = new ContextInformation
                                                {
                                                    ContainingSymbolInfo = invExprSymbolInfo,
                                                    CallerSymbolInfo = context.ContainingSymbol
                                                };
                                                TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, invExprSymbolInfo.Parameters[i]));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public void AnalyzeSimpleAssignmentExpression(SyntaxNodeAnalysisContext context)
        {
            var simpleAssExpr = context.Node;
            if (simpleAssExpr.Kind().Equals(SyntaxKind.SimpleAssignmentExpression))
            {
                var simpleAssignExpr = (AssignmentExpressionSyntax)simpleAssExpr;

                //Check Only For MemberAcessExpressionSyntax Nodes
                if (simpleAssignExpr.ChildNodes().OfType<MemberAccessExpressionSyntax>().FirstOrDefault() != null)
                {
                    //Get the invocator
                    var invocator = simpleAssignExpr.ChildNodes().OfType<MemberAccessExpressionSyntax>().FirstOrDefault().ChildNodes().OfType<IdentifierNameSyntax>().FirstOrDefault();

                    var invocatorSymbolInfo = context.SemanticModel.GetSymbolInfo(invocator).Symbol;
                    if (invocatorSymbolInfo != null)
                    {
                        if (invocatorSymbolInfo.Kind.Equals(SymbolKind.Local))
                        {
                            var localInvocatorSymbolInfo = (ILocalSymbol)invocatorSymbolInfo;

                            var leftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(simpleAssignExpr.Left).Symbol;
                            var rightExprSymbolInfo = context.SemanticModel.GetSymbolInfo(simpleAssignExpr.Right).Symbol;


                            //Check if right expression is sanitized
                            if (rightExprSymbolInfo != null && leftExprSymbolInfo != null)
                            {
                                var taintedRightExprSymbolInfo = IsTaintedValueExists(rightExprSymbolInfo.ContainingSymbol, rightExprSymbolInfo);
                                if (!taintedRightExprSymbolInfo.IsTainted)
                                {
                                    //Sanitize the left expression if the right expression value is not tainted
                                    var taintedLeftExprSymbolInfo = IsTaintedValueExists(leftExprSymbolInfo.ContainingSymbol, leftExprSymbolInfo);
                                    if (taintedLeftExprSymbolInfo.IsTainted)
                                    {
                                        //In order to make object sensitive, identifier symbol info should be retrieved
                                        var identifierLeftExprNodes = simpleAssignExpr.Left.ChildNodes().OfType<IdentifierNameSyntax>();
                                        ISymbol identifierLeftExprSymbolInfo = null;
                                        if (identifierLeftExprNodes.Count() > 0)
                                        {
                                            identifierLeftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierLeftExprNodes.FirstOrDefault()).Symbol;
                                        }
                                        SanitizeTaintValue(leftExprSymbolInfo.ContainingSymbol, leftExprSymbolInfo, identifierLeftExprSymbolInfo);
                                    }
                                }
                            }
                        }
                    }
                }
                else if (simpleAssExpr.IsKind(SyntaxKind.SimpleAssignmentExpression))
                {
                    var simpleAssignmentExpr = (AssignmentExpressionSyntax)simpleAssExpr;
                    var leftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(simpleAssignmentExpr.Left).Symbol;
                    var rightExprSymbolInfo = context.SemanticModel.GetSymbolInfo(simpleAssignmentExpr.Right).Symbol;

                    //Check for tainted values
                    if (rightExprSymbolInfo != null && leftExprSymbolInfo != null)
                    {
                        var taintedRightExprSymbolInfo = IsTaintedValueExists(rightExprSymbolInfo.ContainingSymbol, rightExprSymbolInfo);
                        if (taintedRightExprSymbolInfo.IsTainted)
                        {
                            var taintedLeftExprSymbolInfo = IsTaintedValueExists(leftExprSymbolInfo.ContainingSymbol, leftExprSymbolInfo);
                            if (!taintedLeftExprSymbolInfo.IsTainted)
                            {
                                lock (TaintedValuesDictionary)
                                {
                                    ContextInformation contextInformation = new ContextInformation
                                    {
                                        ContainingSymbolInfo = leftExprSymbolInfo.ContainingSymbol
                                    };
                                    TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, leftExprSymbolInfo));
                                }
                            }
                            ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, simpleAssExpr.GetLocation(), taintedRightExprSymbolInfo.TaintedContextInformation);
                        }
                    }

                    //Check if tainted variables are santized
                    if (leftExprSymbolInfo != null)
                    {
                        var taintedLeftExprSymbolInfo = IsTaintedValueExists(leftExprSymbolInfo.ContainingSymbol, leftExprSymbolInfo);
                        if (taintedLeftExprSymbolInfo.IsTainted)
                        {
                            if (rightExprSymbolInfo != null)
                            {
                                var taintedRightExprSymbolInfo = IsTaintedValueExists(rightExprSymbolInfo.ContainingSymbol, rightExprSymbolInfo);
                                if (!taintedRightExprSymbolInfo.IsTainted)
                                {
                                    //Sanitize the value in the local TaintedValueDictionary
                                    if (TaintedValuesDictionary.Count != 0)
                                    {
                                        lock (TaintedValuesDictionary)
                                        {
                                            ContextInformation contextInformation = new ContextInformation
                                            {
                                                ContainingSymbolInfo = leftExprSymbolInfo.ContainingSymbol
                                            };
                                            TaintedValuesDictionary.Remove(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, leftExprSymbolInfo));
                                        }
                                    }
                                    //Sanitize the value in the global TaintedContextDictionary as well. 
                                    //Sanitizing a method parameter would sanitize the parameter in caller as well as callee
                                    //In order to make object sensitive, identifier symbol info should be retrieved
                                    var identifierLeftExprNodes = simpleAssignExpr.Left.ChildNodes().OfType<IdentifierNameSyntax>();
                                    ISymbol identifierLeftExprSymbolInfo = null;
                                    if (identifierLeftExprNodes.Count() > 0)
                                    {
                                        identifierLeftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierLeftExprNodes.FirstOrDefault()).Symbol;
                                    }
                                    SanitizeTaintValue(leftExprSymbolInfo.ContainingSymbol, leftExprSymbolInfo, identifierLeftExprSymbolInfo);
                                }
                            }
                        }
                    }
                }
            }
        }

        public void AnalyzeLocalDeclarationStatement(SyntaxNodeAnalysisContext context)
        {

            var localDeclarationStatement = context.Node;
            LocalDeclarationStatementVisitor localDeclarationStatementVisitor = new LocalDeclarationStatementVisitor();
            localDeclarationStatementVisitor.Visit(localDeclarationStatement);

            var isIdentifierNameNode = localDeclarationStatementVisitor.GetIdentifierNameSyntaxResult();
            if (isIdentifierNameNode.IsIdentifierPresent)
            {
                var identifierSymbolInfo = context.SemanticModel.GetSymbolInfo(isIdentifierNameNode.IdentifierNameSyntaxNode).Symbol;
                if (identifierSymbolInfo != null && identifierSymbolInfo.ContainingSymbol != null)
                {
                    var taintedIdentifierSymbolInfo = IsTaintedValueExists(identifierSymbolInfo.ContainingSymbol, identifierSymbolInfo);
                    if (taintedIdentifierSymbolInfo.IsTainted)
                    {
                        var declaratorSymbolInfo = context.SemanticModel.GetDeclaredSymbol(isIdentifierNameNode.VariableDeclarator);
                        var taintedDeclaratorSymbolInfo = IsTaintedValueExists(declaratorSymbolInfo.ContainingSymbol, declaratorSymbolInfo);
                        if (!taintedDeclaratorSymbolInfo.IsTainted)
                        {
                            lock (TaintedValuesDictionary)
                            {
                                ContextInformation contextInformation = new ContextInformation
                                {
                                    ContainingSymbolInfo = declaratorSymbolInfo.ContainingSymbol
                                };
                                TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, declaratorSymbolInfo));
                            }
                        }
                        ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, localDeclarationStatement.GetLocation(), taintedIdentifierSymbolInfo.TaintedContextInformation);

                    }
                }
            }

            var isArrayInitializerPresent = localDeclarationStatementVisitor.GetByteArrayResult();
            if (isArrayInitializerPresent.IsArrayInitializer)
            {
                //Adding to Tainted Dictionary for all Byte ArrayInitializer Types
                var nodeSymbolInfo = context.SemanticModel.GetDeclaredSymbol(isArrayInitializerPresent.DeclaratorSyntax);
                var taintedNodeSymbolInfo = IsTaintedValueExists(nodeSymbolInfo.ContainingSymbol, nodeSymbolInfo, null);
                if (!taintedNodeSymbolInfo.IsTainted)
                {
                    lock (TaintedValuesDictionary)
                    {
                        ContextInformation contextInformation = new ContextInformation
                        {
                            ContainingSymbolInfo = nodeSymbolInfo.ContainingSymbol
                        };
                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, nodeSymbolInfo));
                    }
                }
                if (!localDeclarationStatement.Kind().Equals(SyntaxKind.FieldDeclaration))
                {
                    var dataFlowAnalysisResult = context.SemanticModel.AnalyzeDataFlow(localDeclarationStatement);
                    if (dataFlowAnalysisResult.ReadOutside.Contains(nodeSymbolInfo))
                    {
                        var diagnsotics = Diagnostic.Create(HardCodedCheckViolationRule, localDeclarationStatement.GetLocation());
                        _diagnostics.Add(diagnsotics);
                        //context.ReportDiagnostic(diagnsotics);
                    }
                }
            }

            var isStringInitializerPresent = localDeclarationStatementVisitor.GetStringLiteralResult();
            if (isStringInitializerPresent.IsStringLiteralInitializer)
            {
                //Adding to Tainted Dictionary for all Byte ArrayInitializer Types
                var nodeSymbolInfo = context.SemanticModel.GetDeclaredSymbol(isStringInitializerPresent.DeclaratorSyntax);
                var taintedNodeSymbolInfo = IsTaintedValueExists(nodeSymbolInfo.ContainingSymbol, nodeSymbolInfo);
                if (!taintedNodeSymbolInfo.IsTainted)
                {
                    lock (TaintedValuesDictionary)
                    {
                        ContextInformation contextInformation = new ContextInformation
                        {
                            ContainingSymbolInfo = nodeSymbolInfo.ContainingSymbol
                        };
                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, nodeSymbolInfo));
                    }
                }

                if (!localDeclarationStatement.Kind().Equals(SyntaxKind.FieldDeclaration))
                {
                    var dataFlowAnalysisResult = context.SemanticModel.AnalyzeDataFlow(localDeclarationStatement);
                    if (dataFlowAnalysisResult.ReadOutside.Contains(nodeSymbolInfo))
                    {
                        var diagnsotics = Diagnostic.Create(HardCodedCheckViolationRule, localDeclarationStatement.GetLocation());
                        _diagnostics.Add(diagnsotics);
                        //context.ReportDiagnostic(diagnsotics);
                    }
                }
                //For field declarations report diagnostics without performing data flow analysis. Data flow analysis works within code blocks only
                else if (localDeclarationStatement.Kind().Equals(SyntaxKind.FieldDeclaration))
                {
                    var diagnsotics = Diagnostic.Create(HardCodedCheckViolationRule, localDeclarationStatement.GetLocation());
                    _diagnostics.Add(diagnsotics);
                    //context.ReportDiagnostic(diagnsotics);
                }
            }
        }

        public void AnalyzeExpressionStatement(SyntaxNodeAnalysisContext context)
        {

            var expressionStatementNode = (ExpressionStatementSyntax)context.Node;
            ExpressionStatementVisitor expressionStatementVisitor = new ExpressionStatementVisitor();
            expressionStatementVisitor.VisitExpressionStatement(expressionStatementNode);
            var StringLiteralPresentResult = expressionStatementVisitor.GetAssignmentExpressionResult();

            if (StringLiteralPresentResult.IsStringLiteralInitializer && StringLiteralPresentResult.ExpressionSyntax.Left != null)
            {
                var leftExpressionSymbolInfo = context.SemanticModel.GetSymbolInfo(StringLiteralPresentResult.ExpressionSyntax.Left).Symbol;

                //In order to make object sensitive, identifer symbol info should be retrieved
                var identifierLeftExprNodes = StringLiteralPresentResult.ExpressionSyntax.Left.ChildNodes().OfType<IdentifierNameSyntax>();
                ISymbol identifierLeftExprSymbolInfo = null;
                if (identifierLeftExprNodes.Count() > 0)
                {
                    identifierLeftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierLeftExprNodes.FirstOrDefault()).Symbol;
                }

                var TaintedInformation = IsTaintedValueExists(leftExpressionSymbolInfo.ContainingSymbol, leftExpressionSymbolInfo, identifierLeftExprSymbolInfo);
                if (!TaintedInformation.IsTainted)
                {
                    lock (TaintedValuesDictionary)
                    {
                        ContextInformation contextInformation = new ContextInformation
                        {
                            ContainingSymbolInfo = leftExpressionSymbolInfo.ContainingSymbol,
                            ContainingObjectSymbolInfo = identifierLeftExprSymbolInfo
                        };
                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, leftExpressionSymbolInfo));
                    }
                }
                var diagnostics = Diagnostic.Create(HardCodedCheckViolationRule, StringLiteralPresentResult.ExpressionSyntax.GetLocation());
                _diagnostics.Add(diagnostics);
                //context.ReportDiagnostic(diagnostics);
            }

            var simpleAssignmentExpression = expressionStatementNode.ChildNodes().OfType<AssignmentExpressionSyntax>();
            foreach (var assignmentExpression in simpleAssignmentExpression)
            {
                if (assignmentExpression.IsKind(SyntaxKind.SimpleAssignmentExpression) && assignmentExpression.Left != null && assignmentExpression.Right != null)
                {
                    var rightSymbolInfo = context.SemanticModel.GetSymbolInfo(assignmentExpression.Right);

                    //In order to make object sensitive, identifer symbol info should be retrieved
                    var identifierRightExprNodes = assignmentExpression.Right.ChildNodes().OfType<IdentifierNameSyntax>();
                    ISymbol identifierRightExprSymbolInfo = null;
                    if (identifierRightExprNodes.Count() > 0)
                    {
                        identifierRightExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierRightExprNodes.FirstOrDefault()).Symbol;
                    }

                    if (rightSymbolInfo.Symbol != null)
                    {
                        ISymbol identifierLeftExprSymbolInfo = null;
                        var taintedRightSymbolInfo = IsTaintedValueExists(rightSymbolInfo.Symbol.ContainingSymbol, rightSymbolInfo.Symbol, identifierRightExprSymbolInfo);
                        if (taintedRightSymbolInfo.IsTainted)
                        {
                            var leftSymbolInfo = context.SemanticModel.GetSymbolInfo(assignmentExpression.Left);

                            //In order to make object sensitive, identifier symbol info should be retrieved
                            var identifierLeftExprNodes = assignmentExpression.Left.ChildNodes().OfType<IdentifierNameSyntax>();

                            if (identifierLeftExprNodes.Count() > 0)
                            {
                                identifierLeftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierLeftExprNodes.FirstOrDefault()).Symbol;
                            }
                            if (leftSymbolInfo.Symbol != null)
                            {
                                var taintedLeftSymbolInfo = IsTaintedValueExists(leftSymbolInfo.Symbol.ContainingSymbol, leftSymbolInfo.Symbol, identifierLeftExprSymbolInfo);
                                if (!taintedLeftSymbolInfo.IsTainted)
                                {
                                    lock (TaintedValuesDictionary)
                                    {
                                        ContextInformation contextInformation = new ContextInformation
                                        {
                                            ContainingSymbolInfo = leftSymbolInfo.Symbol.ContainingSymbol,
                                            ContainingObjectSymbolInfo = identifierLeftExprSymbolInfo
                                        };
                                        TaintedValuesDictionary.Add(new KeyValuePair<ContextInformation, ISymbol>(contextInformation, leftSymbolInfo.Symbol));
                                    }
                                }
                            }
                            ReportDiagnostics(context, HardCodedContextCheckViolationRule, HardCodedCheckViolationRule, expressionStatementNode.GetLocation(), taintedRightSymbolInfo.TaintedContextInformation);
                            /*var diagnostics = (taintedRightSymbolInfo.TaintedContextInformation.CallerSymbolInfo != null) ? Diagnostic.Create(HardCodedContextCheckViolationRule, expressionStatementNode.GetLocation(), taintedRightSymbolInfo.TaintedContextInformation.CallerSymbolInfo.ToString()) : Diagnostic.Create(HardCodedCheckViolationRule, expressionStatementNode.GetLocation());
                            context.ReportDiagnostic(diagnostics);*/
                        }
                        else
                        {
                            var taintedRightInfo = IsTaintedValueExists(rightSymbolInfo.Symbol.ContainingSymbol, rightSymbolInfo.Symbol, identifierRightExprSymbolInfo);
                            if (!taintedRightInfo.IsTainted)
                            {
                                var leftSymbolInfo = context.SemanticModel.GetSymbolInfo(assignmentExpression.Left);

                                if (leftSymbolInfo.Symbol != null)
                                {
                                    //In order to make object sensitive, identifier symbol info should be retrieved
                                    var identifierLeftExprNodes = assignmentExpression.Left.ChildNodes().OfType<IdentifierNameSyntax>();

                                    if (identifierLeftExprNodes.Count() > 0)
                                    {
                                        identifierLeftExprSymbolInfo = context.SemanticModel.GetSymbolInfo(identifierLeftExprNodes.FirstOrDefault()).Symbol;
                                    }
                                    SanitizeTaintValue(leftSymbolInfo.Symbol.ContainingSymbol, leftSymbolInfo.Symbol, identifierLeftExprSymbolInfo);
                                }
                            }
                        }
                    }
                }
            }
        }

        private TaintQueryInformation IsTaintedValueExists(ISymbol containingMethod, ISymbol nodeInfo, ISymbol containingObject = null)
        {
            TaintQueryInformation taintQueryResult = new TaintQueryInformation();
            try
            {
                if (containingMethod != null && nodeInfo != null && containingObject == null)
                {
                    TaintQueryInformation taintQueryInformation = new TaintQueryInformation
                    {
                        IsTainted = false,
                        TaintedContextInformation = new List<ContextInformation>()
                    };
                    lock (TaintedValuesDictionary)
                    {
                        //If tainted values are not present in ContextDictionary check in Current TaintedValuesDictionary
                        //TaintedValuesDictionary need not be checked for context, because it contains only current context values
                        foreach (var taintedValue in TaintedValuesDictionary)
                        {
                            if (taintedValue.Key.ContainingSymbolInfo != null)
                            {
                                bool taintedValuePresent = (taintedValue.Key.ContainingSymbolInfo.ToString().Equals(containingMethod.ToString()) && taintedValue.Value.Kind.Equals(nodeInfo.Kind) && taintedValue.Value.ToString().Equals(nodeInfo.ToString()) && taintedValue.Value.Name.ToString().Equals(nodeInfo.Name.ToString())) ? true : false;

                                if (taintedValuePresent)
                                {
                                    taintQueryInformation.IsTainted = true;
                                    taintQueryInformation.TaintedContextInformation.Add(taintedValue.Key);
                                    /*return new TaintQueryInformation
                                    {
                                        IsTainted = true,
                                        TaintedContextInformation = taintedValue.Key
                                    };*/
                                }
                            }
                        }
                    }
                    taintQueryResult = taintQueryInformation;
                }
                else if (containingMethod != null && nodeInfo != null && containingObject != null)
                {
                    TaintQueryInformation taintQueryInformation = new TaintQueryInformation
                    {
                        IsTainted = false,
                        TaintedContextInformation = new List<ContextInformation>()
                    };
                    lock (TaintedValuesDictionary)
                    {
                        //If tainted values are not present in ContextDictionary check in Current TaintedValuesDictionary
                        //TaintedValuesDictionary need not be checked for context, because it contains only current context values
                        foreach (var taintedValue in TaintedValuesDictionary)
                        {
                            if (taintedValue.Key.ContainingObjectSymbolInfo != null && taintedValue.Key.ContainingSymbolInfo != null)
                            {
                                bool taintedValuePresent = (taintedValue.Key.ContainingSymbolInfo.ToString().Equals(containingMethod.ToString()) && taintedValue.Key.ContainingObjectSymbolInfo.ToString().Equals(containingObject.ToString()) && taintedValue.Value.Kind.Equals(nodeInfo.Kind) && taintedValue.Value.ToString().Equals(nodeInfo.ToString()) && taintedValue.Value.Name.ToString().Equals(nodeInfo.Name.ToString())) ? true : false;

                                if (taintedValuePresent)
                                {
                                    taintQueryInformation.IsTainted = true;
                                    taintQueryInformation.TaintedContextInformation.Add(taintedValue.Key);
                                }
                            }
                        }
                    }
                    taintQueryResult = taintQueryInformation;
                }
            }
            catch (Exception ex)
            {
                //Log the exception into a log file
            }
            return taintQueryResult;
        }

        private void ReportDiagnostics(SyntaxNodeAnalysisContext context, DiagnosticDescriptor descriptionContextInfo, DiagnosticDescriptor descriptorInfo, Location location, List<ContextInformation> contextInformationList)
        {
            foreach (var contextInformation in contextInformationList)
            {
                if (contextInformation.CallerSymbolInfo != null)
                {
                    var diagnostic = Diagnostic.Create(descriptionContextInfo, location, contextInformation.CallerSymbolInfo.ToString());
                    lock(_diagnostics)
                    {
                        _diagnostics.Add(diagnostic);
                    }
                    //context.ReportDiagnostic(diagnostic);
                }
                else
                {
                    var diagnostic = Diagnostic.Create(descriptorInfo, location);
                    lock(_diagnostics)
                    {
                        _diagnostics.Add(diagnostic);
                    }
                    //context.ReportDiagnostic(diagnostic);
                }
            }
        }

        private void SanitizeTaintValue(ISymbol containingMethod, ISymbol nodeInfo, ISymbol containingObject)
        {
            List<KeyValuePair<ContextInformation, ISymbol>> sanitizedValues = new List<KeyValuePair<ContextInformation, ISymbol>>();

            //TaintedValuesDictionary need not be checked for context, because it contains only current context values
            lock (TaintedValuesDictionary)
            {
                foreach (var taintedValue in TaintedValuesDictionary)
                {
                    if (containingMethod != null && nodeInfo != null && containingObject == null)
                    {
                        bool taintedValuePresent = (taintedValue.Value.Kind.Equals(nodeInfo.Kind) && taintedValue.Value.ToString().Equals(nodeInfo.ToString()) && taintedValue.Value.Name.ToString().Equals(nodeInfo.Name.ToString())) ? true : false;
                        if (taintedValuePresent)
                        {
                            lock (sanitizedValues)
                            {
                                if (!sanitizedValues.Contains(new KeyValuePair<ContextInformation, ISymbol>(taintedValue.Key, taintedValue.Value)))
                                {
                                    sanitizedValues.Add(new KeyValuePair<ContextInformation, ISymbol>(taintedValue.Key, taintedValue.Value));
                                }
                            }
                        }
                    }
                    else if (containingMethod != null && nodeInfo != null && containingObject != null)
                    {
                        if (taintedValue.Key.ContainingObjectSymbolInfo != null)
                        {
                            bool taintedValuePresent = (taintedValue.Key.ContainingObjectSymbolInfo.ToString().Equals(containingObject.ToString()) && taintedValue.Value.Kind.Equals(nodeInfo.Kind) && taintedValue.Value.ToString().Equals(nodeInfo.ToString()) && taintedValue.Value.Name.ToString().Equals(nodeInfo.Name.ToString())) ? true : false;
                            if (taintedValuePresent)
                            {
                                lock (sanitizedValues)
                                {
                                    if (!sanitizedValues.Contains(new KeyValuePair<ContextInformation, ISymbol>(taintedValue.Key, taintedValue.Value)))
                                    {
                                        sanitizedValues.Add(new KeyValuePair<ContextInformation, ISymbol>(taintedValue.Key, taintedValue.Value));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            lock (sanitizedValues)
            {
                //Remove all the sanitized variables
                foreach (var sanitizedVariables in sanitizedValues)
                {
                    lock (TaintedValuesDictionary)
                    {
                        TaintedValuesDictionary.Remove(sanitizedVariables);
                    }
                }
            }
        }

        private static VariableDeclaratorSyntaxResult GetVariableDeclarator(SyntaxNode syntaxNode, SyntaxNodeAnalysisContext context)
        {
            var variableDeclaratorSyntax = syntaxNode.AncestorsAndSelf().OfType<VariableDeclaratorSyntax>();
            VariableDeclaratorSyntaxResult variableDeclaratorSyntaxResult = new VariableDeclaratorSyntaxResult();
            if (variableDeclaratorSyntax.Count() > 0)
            {
                var variableDeclaratorSymbolInfo = context.SemanticModel.GetDeclaredSymbol(variableDeclaratorSyntax.FirstOrDefault());
                if (variableDeclaratorSymbolInfo.Kind.Equals(SymbolKind.Local))
                {
                    var variableDeclaratorLocalInfo = (ILocalSymbol)variableDeclaratorSymbolInfo;
                    if (variableDeclaratorLocalInfo.Type.ToString().Equals("byte[]"))
                    {
                        variableDeclaratorSyntaxResult.IsVariableDeclaratorSyntaxPresent = true;
                        variableDeclaratorSyntaxResult.VariableDeclaratorSyntaxNode = variableDeclaratorSyntax.FirstOrDefault();
                        variableDeclaratorSyntaxResult.VariableDeclaratorSymbolInfo = variableDeclaratorSymbolInfo;

                    }

                }

            }

            return variableDeclaratorSyntaxResult;
        }

        public void AnalyzeCompilationEndAction(CompilationAnalysisContext context)
        {
            foreach(var diagnostic in _diagnostics)
            {
                context.ReportDiagnostic(diagnostic);
            }

            TaintedValuesDictionary.Clear();
        }

    }    
}
