using System;
using System.Collections.Generic;
using System.Diagnostics;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public class InternalState
    {
        public DnsQuestionRecord Question;
        public string? ZoneCut;

        public bool DnssecValidationState;
        public IReadOnlyList<DnsResourceRecord>? LastDSRecords;

        public int HopCount;
        public IList<NameServerAddress>? NameServers;
        public int NameServerIndex;

        public DnsDatagram? LastResponse;
        public Exception? LastException;

        private const int MAX_HOP_LIMIT = 64;

        public InternalState()
        {
            NormalizeAndValidate();
        }

        public InternalState(
            DnsQuestionRecord question,
            string? zoneCut,
            bool dnssecValidationState,
            IReadOnlyList<DnsResourceRecord>? lastDSRecords,
            IList<NameServerAddress> nameServers,
            int nameServerIndex,
            int hopCount,
            DnsDatagram? lastResponse,
            Exception? lastException)
        {
            Question = question;
            ZoneCut = zoneCut;
            DnssecValidationState = dnssecValidationState;
            LastDSRecords = lastDSRecords;
            NameServers = nameServers;
            NameServerIndex = nameServerIndex;
            HopCount = hopCount;
            LastResponse = lastResponse;
            LastException = lastException;

            NormalizeAndValidate();
        }

        private void NormalizeAndValidate()
        {
            // Normalize zone-cut and name casing deterministically
            ZoneCut = ZoneCut?.ToLowerInvariant();

            // Question must always exist
            if (Question == null)
                throw new InvalidOperationException("InternalState requires a Question value.");

            // Hop count monotonic safety
            if (HopCount < 0 || HopCount > MAX_HOP_LIMIT)
                throw new InvalidOperationException($"Hop bound violated: {HopCount}");

            // Clamp invalid indices defensively
            if (NameServers != null && NameServers.Count > 0)
            {
                if (NameServerIndex < 0)
                    NameServerIndex = 0;

                if (NameServerIndex >= NameServers.Count)
                    NameServerIndex = NameServers.Count - 1;
            }

            // DNSSEC downgrade protection
            if (DnssecValidationState &&
                ZoneCut != null &&
                LastDSRecords == null &&
                Question?.Name != ZoneCut)
            {
                // DS chain should not silently reset within same zone cut
                // if reset is legitimate, caller should replace the frame
                throw new InvalidOperationException(
                    "Unexpected DS chain reset during DNSSEC validation.");
            }

            DebugAssertInvariants();
        }

        [Conditional("DEBUG")]
        private void DebugAssertInvariants()
        {
            Debug.Assert(Question != null);
            Debug.Assert(HopCount <= MAX_HOP_LIMIT);
            Debug.Assert(NameServerIndex >= 0);
        }

        public InternalState DeepClone()
        {
            // Preserve signature — but avoid unsafe stale-data resurrection
            var clone = new InternalState(
                question: Question,
                zoneCut: ZoneCut,
                dnssecValidationState: DnssecValidationState,
                lastDSRecords: LastDSRecords,
                nameServers: NameServers is null ? null : new List<NameServerAddress>(NameServers),
                nameServerIndex: NameServerIndex,
                hopCount: HopCount,
                lastResponse: null,      // transient fields are intentionally not cloned
                lastException: null
            );

            return clone;
        }
    }
}
