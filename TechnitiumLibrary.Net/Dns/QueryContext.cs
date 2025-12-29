using System;
using System.Collections.Generic;

namespace TechnitiumLibrary.Net.Dns
{
    public sealed class QueryContext
    {
        public Guid QueryId { get; }

        public InternalState Head { get; set; }

        public Stack<InternalState> Stack { get; }

        public QueryContext(Guid queryId, InternalState head)
        {
            QueryId = queryId;
            Head = head;
            Stack = new Stack<InternalState>();
        }
    }

}
