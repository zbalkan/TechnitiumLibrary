namespace TechnitiumLibrary.Net.Dns
{
    internal enum ResolverDecisionKind
    {
        ReturnAnswer,
        DelegationTransition,
        UnwindStack,
        RetryWithQNameMinimization,
        ContinueNextServer
    }
}