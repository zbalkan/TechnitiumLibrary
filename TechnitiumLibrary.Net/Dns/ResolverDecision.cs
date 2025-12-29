namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class ResolverDecision
    {
        public ResolverDecisionKind Kind { get; }
        public DnsDatagram? Response { get; }
        public InternalState? NewFrame { get; }

        public ResolverDecision(
            ResolverDecisionKind kind,
            DnsDatagram? response = null,
            InternalState? newFrame = null)
        {
            Kind = kind;
            Response = response;
            NewFrame = newFrame;
        }

        /// <summary>
        /// Applies unwind transition (used for A/AAAA/DS glue resolution stack pop)
        /// </summary>
        public void ApplyUnwind()
        {
            // no-op here — actual unwind is handled by caller
            // but the decision models intent explicitly
        }
    }
}
