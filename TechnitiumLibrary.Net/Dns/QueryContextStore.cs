using System;
using System.Collections.Concurrent;

namespace TechnitiumLibrary.Net.Dns
{
    public sealed class QueryContextStore
    {
        private static readonly Lazy<QueryContextStore> _instance =
            new(() => new QueryContextStore());

        public static QueryContextStore Instance => _instance.Value;

        private readonly ConcurrentDictionary<Guid, QueryContext> _contexts =
            new();

        private QueryContextStore() { }

        public QueryContext Create(Guid id, InternalState head)
        {
            var ctx = new QueryContext(id, head);
            _contexts[id] = ctx;
            return ctx;
        }

        public bool TryGet(Guid id, out QueryContext ctx)
            => _contexts.TryGetValue(id, out ctx);

        public QueryContext Get(Guid id)
            => _contexts[id];

        public bool Remove(Guid id)
            => _contexts.TryRemove(id, out _);
    }

}
