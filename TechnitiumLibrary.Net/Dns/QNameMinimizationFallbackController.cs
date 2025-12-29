using System;

namespace TechnitiumLibrary.Net.Dns
{
    /// <summary>
    /// Applies fallback behaviour when QNAME minimization encounters
    /// ambiguous results and the resolver must retry using a deeper
    /// label or disable minimization entirely.
    /// </summary>
    internal sealed class QNameMinimizationFallbackController
    {
        private readonly QueryContext _ctx;

        public QNameMinimizationFallbackController(QueryContext ctx)
        {
            _ctx = ctx;
        }

        /// <summary>
        /// Modifies the HEAD frame in-place to reflect a QNAME-MIN
        /// fallback retry. Caller must rewind the iterator so the same
        /// nameserver is retried.
        /// </summary>
        public void Apply()
        {
            var q = _ctx.Head.Question;

            //
            // Case 1:
            // Minimized == full QNAME
            // → disable minimization and retry real type
            //
            if (q.Name.Equals(q.MinimizedName, StringComparison.OrdinalIgnoreCase))
            {
                if (q.Type != q.MinimizedType)
                {
                    // NO-DATA for minimized type → retry full type
                    q.ZoneCut = null;

                    // retry same server
                    _ctx.Head.NameServerIndex--;
                }

                return;
            }

            //
            // Case 2:
            // Promote minimized label to new zone cut
            //
            q.ZoneCut = q.MinimizedName;

            // retry same server at new depth
            _ctx.Head.NameServerIndex--;
        }
    }
}
