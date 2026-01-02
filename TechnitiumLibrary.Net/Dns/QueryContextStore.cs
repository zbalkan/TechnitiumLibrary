using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace TechnitiumLibrary.Net.Dns
{
    public sealed class QueryContextStore
    {
        private static readonly Lazy<QueryContextStore> _instance =
            new(() => new QueryContextStore());

        public static QueryContextStore Instance => _instance.Value;

        // One context per active query — never evicted automatically
        private readonly ConcurrentDictionary<Guid, TrackedContext> _contexts = new();

        private QueryContextStore() { }

        // Tracked wrapper retained to keep ABI compatibility
        private sealed class TrackedContext
        {
            public readonly QueryContext Context;

            public TrackedContext(QueryContext ctx)
            {
                Context = ctx;
            }
        }

        // ---- Factory ----
        // Strict create: a context must not already exist for this query id
        public QueryContext Create(Guid id, InternalState head, int? ttlAccessBudget = null)
        {
            var ctx = new QueryContext(id, head);
            var tracked = new TrackedContext(ctx);

            if (!_contexts.TryAdd(id, tracked))
                throw new InvalidOperationException(
                    $"QueryContext already exists for active query {id}");

            return ctx;
        }

        // ---- Lookup (non-mutating) ----
        public bool TryGet(Guid id, out QueryContext ctx)
        {
            if (_contexts.TryGetValue(id, out var tracked))
            {
                ctx = tracked.Context;
                return true;
            }

            ctx = null!;
            return false;
        }

        public QueryContext Get(Guid id)
        {
            if (!_contexts.TryGetValue(id, out var tracked))
                throw new KeyNotFoundException(
                    $"QueryContext not found for active query {id}");

            return tracked.Context;
        }

        // ---- Removal (terminal only) ----
        // Called when a final response is emitted
        public bool Remove(Guid id) => CompleteAndRemove(id);

        public bool CompleteAndRemove(Guid id)
        {
            return _contexts.TryRemove(id, out _);
        }
    }
}
