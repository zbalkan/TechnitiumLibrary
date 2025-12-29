using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace TechnitiumLibrary.Net.Dns
{
    public sealed class QueryContext
    {
        private const int DEFAULT_MAX_STACK_DEPTH = 32;
        private const int DEFAULT_MAX_FRAME_COUNT = 128;

        public Guid QueryId { get; }

        // Monotonic generation counter to detect stale heads
        public long HeadGeneration { get; private set; }

        public InternalState Head
        {
            get => _head;
            set => ReplaceHead(value);
        }

        private InternalState _head;

        public Stack<InternalState> Stack { get; }

        // Total frames ever created for this query
        private int _frameCount;

        public int MaxStackDepth { get; }
        public int MaxFrameCount { get; }

        public QueryContext(
            Guid queryId,
            InternalState head,
            int maxStackDepth = DEFAULT_MAX_STACK_DEPTH,
            int maxFrameCount = DEFAULT_MAX_FRAME_COUNT)
        {
            if (head == null)
                throw new ArgumentNullException(nameof(head));

            QueryId = queryId;

            MaxStackDepth = Math.Max(1, maxStackDepth);
            MaxFrameCount = Math.Max(MaxStackDepth, maxFrameCount);

            _head = ValidateNewFrame(head);

            Stack = new Stack<InternalState>();
            HeadGeneration = 1;
            _frameCount = 1;
        }

        public bool TryPushFrame(InternalState frame)
        {
            if (frame == null)
                throw new ArgumentNullException(nameof(frame));

            // Defensive caps to block recursion & algorithmic complexity attacks
            if (Stack.Count >= MaxStackDepth)
                return false;

            if (_frameCount >= MaxFrameCount)
                return false;

            frame = ValidateNewFrame(frame);

            Stack.Push(frame);

            _frameCount++;
            TraceFrameGrowth();

            return true;
        }

        public bool TryPopFrame(out InternalState? frame)
        {
            frame = null;

            if (Stack.Count == 0)
                return false;

            frame = Stack.Pop();
            return true;
        }

        private void ReplaceHead(InternalState newHead)
        {
            if (newHead == null)
                throw new ArgumentNullException(nameof(newHead));

            newHead = ValidateNewFrame(newHead);

            _head = newHead;

            unchecked { HeadGeneration++; }
        }

        private static InternalState ValidateNewFrame(InternalState state)
        {
            if (state.Question == null)
                throw new InvalidOperationException("InternalState requires a Question.");

            if (state.HopCount < 0)
                throw new InvalidOperationException("HopCount must be non-negative.");

            if (state.ZoneCut == string.Empty)
                throw new InvalidOperationException("ZoneCut must be null or a valid domain label.");

            return state;
        }

        private void TraceFrameGrowth()
        {
            if (_frameCount >= (MaxFrameCount * 0.75))
            {
                Trace.TraceWarning(
                    $"QueryContext {QueryId} approaching frame limit. " +
                    $"Frames={_frameCount}/{MaxFrameCount}, StackDepth={Stack.Count}/{MaxStackDepth}");
            }
        }
    }
}
