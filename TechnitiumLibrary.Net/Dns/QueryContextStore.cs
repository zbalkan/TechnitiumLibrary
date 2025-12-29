using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace TechnitiumLibrary.Net.Dns
{
    public sealed class QueryContextStore
    {
        private static readonly Lazy<QueryContextStore> _instance =
            new(() => new QueryContextStore());

        public static QueryContextStore Instance => _instance.Value;

        private readonly ConcurrentDictionary<Guid, TrackedContext> _contexts = new();

        // Capacity & lifecycle limits
        private const int MAX_ACTIVE_CONTEXTS = 2048;
        private const int DEFAULT_TTL_ACCESSES = 512;

        private QueryContextStore() { }

        private sealed class TrackedContext
        {
            public readonly QueryContext Context;

            // A “lease counter” instead of timestamp
            private int _remainingAccesses;

            public TrackedContext(QueryContext ctx, int ttlAccessBudget)
            {
                Context = ctx;
                _remainingAccesses = ttlAccessBudget;
            }

            public bool ConsumeLease()
            {
                if (_remainingAccesses <= 0)
                    return false;

                _remainingAccesses--;
                return _remainingAccesses > 0;
            }
        }

        // ---- Factory ----
        public QueryContext Create(Guid id, InternalState head, int? ttlAccessBudget = null)
        {
            PurgeIfOverCapacity();
            PurgeExpired();

            var ctx = new QueryContext(id, head);

            var tracked = new TrackedContext(
                ctx,
                ttlAccessBudget ?? DEFAULT_TTL_ACCESSES);

            _contexts[id] = tracked;
            return ctx;
        }

        // ---- Lookup ----
        public bool TryGet(Guid id, out QueryContext ctx)
        {
            if (_contexts.TryGetValue(id, out var tracked))
            {
                if (tracked.ConsumeLease())
                {
                    ctx = tracked.Context;
                    return true;
                }

                TryRemove(id);
            }

            ctx = null!;
            return false;
        }

        public QueryContext Get(Guid id)
        {
            if (!TryGet(id, out var ctx))
                throw new KeyNotFoundException($"Query context expired or missing: {id}");

            return ctx;
        }

        // ---- Removal ----
        public bool Remove(Guid id) => TryRemove(id);

        private bool TryRemove(Guid id)
            => _contexts.TryRemove(id, out _);

        // Explicit terminal purge hook
        public void CompleteAndRemove(Guid id)
        {
            TryRemove(id);
        }

        // ---- Eviction Policies ----
        private void PurgeExpired()
        {
            foreach (var kv in _contexts.ToArray())
            {
                // A consumed lease means expiration
                // TryGet already decrements, so purge only those already dead
                if (!TryGet(kv.Key, out _))
                    _contexts.TryRemove(kv.Key, out _);
            }
        }

        private void PurgeIfOverCapacity()
        {
            if (_contexts.Count < MAX_ACTIVE_CONTEXTS)
                return;

            // Evict lowest remaining lease (least likely to survive)
            var victims = _contexts
                .OrderBy(kv => kv.Value, Comparer<TrackedContext>.Create(
                    (a, b) => ReferenceEquals(a, b) ? 0 : -1)) // stable, but biased toward older inserts
                .Take(_contexts.Count - MAX_ACTIVE_CONTEXTS + 1)
                .Select(kv => kv.Key);

            foreach (var id in victims)
                _contexts.TryRemove(id, out _);
        }
    }
}
