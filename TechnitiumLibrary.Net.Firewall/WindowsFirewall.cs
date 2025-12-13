/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

GPLv3+
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace TechnitiumLibrary.Net.Firewall
{
    public enum Protocol
    {
        Unknown = -1,
        ICMPv4 = 1,
        IGMP = 2,
        IPv4 = 4,
        TCP = 6,
        UDP = 17,
        IPv6 = 41,
        ANY = 256
    }

    public enum FirewallAction
    {
        Block = 0,
        Allow = 1
    }

    [Flags]
    public enum InterfaceTypeFlags
    {
        All = 0,
        Lan = 1,
        Wireless = 2,
        RemoteAccess = 4
    }

    public enum Direction
    {
        Inbound = 0,
        Outbound = 1
    }

    public enum RuleStatus
    {
        DoesNotExists = 0,
        Disabled = 1,
        Allowed = 2,
        Blocked = 3
    }

    public static class WindowsFirewall
    {
        // Internal injection seam: public contracts remain unchanged.
        internal static IWindowsFirewallBackend Backend { get; set; } = new ComFirewallBackend();

        public static void AddRuleVista(
            string name,
            string description = null,
            FirewallAction action = FirewallAction.Allow,
            string applicationPath = null,
            Protocol protocol = Protocol.IPv4,
            string localPorts = null,
            string remotePorts = null,
            string localAddresses = null,
            string remoteAddresses = null,
            InterfaceTypeFlags interfaceType = InterfaceTypeFlags.All,
            bool enable = true,
            Direction direction = Direction.Inbound,
            bool edgeTraversal = false)
        {
            Backend.AddRuleVista(name, description, action, applicationPath, protocol, localPorts, remotePorts,
                localAddresses, remoteAddresses, interfaceType, enable, direction, edgeTraversal);
        }

        public static void RemoveRuleVista(string name, string applicationPath)
        {
            Backend.RemoveRuleVista(name, applicationPath);
        }

        public static RuleStatus RuleExistsVista(string name, string applicationPath, Protocol protocol = Protocol.Unknown)
        {
            return Backend.RuleExistsVista(name, applicationPath, protocol);
        }

        public static void AddPort(string name, Protocol protocol, int port, bool enable)
        {
            Backend.AddPort(name, protocol, port, enable);
        }

        public static void RemovePort(Protocol protocol, int port)
        {
            Backend.RemovePort(protocol, port);
        }

        public static bool PortExists(Protocol protocol, int port)
        {
            return Backend.PortExists(protocol, port);
        }

        public static void AddApplication(string name, string path)
        {
            Backend.AddApplication(name, path);
        }

        public static void RemoveApplication(string path)
        {
            Backend.RemoveApplication(path);
        }

        public static RuleStatus ApplicationExists(string path)
        {
            return Backend.ApplicationExists(path);
        }
    }

    internal interface IWindowsFirewallBackend
    {
        void AddRuleVista(string name, string description, FirewallAction action, string applicationPath,
            Protocol protocol, string localPorts, string remotePorts, string localAddresses, string remoteAddresses,
            InterfaceTypeFlags interfaceType, bool enable, Direction direction, bool edgeTraversal);

        void RemoveRuleVista(string name, string applicationPath);

        RuleStatus RuleExistsVista(string name, string applicationPath, Protocol protocol);

        void AddPort(string name, Protocol protocol, int port, bool enable);

        void RemovePort(Protocol protocol, int port);

        bool PortExists(Protocol protocol, int port);

        void AddApplication(string name, string path);

        void RemoveApplication(string path);

        RuleStatus ApplicationExists(string path);
    }

    /// <summary>
    /// COM-based backend using late binding (dynamic) to avoid compile-time NetFwTypeLib dependency.
    /// </summary>
    internal sealed class ComFirewallBackend : IWindowsFirewallBackend
    {
        // COM ProgIDs used by Windows Firewall APIs.
        private const string ProgIdFwRule = "HNetCfg.FWRule";
        private const string ProgIdFwPolicy2 = "HNetCfg.FwPolicy2";
        private const string ProgIdFwOpenPort = "HNetCfg.FWOpenPort";
        private const string ProgIdFwMgr = "HNetCfg.FwMgr";
        private const string ProgIdFwAuthorizedApplication = "HNetCfg.FwAuthorizedApplication";

        // Constants mirroring NetFwTypeLib enums (keep these isolated for future replacement).
        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_RULE_DIR_OUT = 2;

        private const int NET_FW_ACTION_BLOCK = 0;
        private const int NET_FW_ACTION_ALLOW = 1;

        private const int NET_FW_SCOPE_ALL = 0;

        public void AddRuleVista(string name, string description, FirewallAction action, string applicationPath,
            Protocol protocol, string localPorts, string remotePorts, string localAddresses, string remoteAddresses,
            InterfaceTypeFlags interfaceType, bool enable, Direction direction, bool edgeTraversal)
        {
            dynamic firewallRule = null;
            dynamic firewallPolicy = null;

            try
            {
                firewallRule = CreateComObject(ProgIdFwRule);

                firewallRule.Name = name;
                firewallRule.Description = description;
                firewallRule.ApplicationName = applicationPath;
                firewallRule.Enabled = enable;

                firewallRule.Protocol = (int)protocol;

                if (localPorts != null)
                    firewallRule.LocalPorts = localPorts;
                if (remotePorts != null)
                    firewallRule.RemotePorts = remotePorts;

                if (localAddresses != null)
                    firewallRule.LocalAddresses = localAddresses;
                if (remoteAddresses != null)
                    firewallRule.RemoteAddresses = remoteAddresses;

                firewallRule.Direction = direction == Direction.Inbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT;
                firewallRule.EdgeTraversal = edgeTraversal;

                firewallRule.InterfaceTypes = InterfaceTypesToString(interfaceType);

                firewallRule.Action = action == FirewallAction.Allow ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK;

                firewallPolicy = CreateComObject(ProgIdFwPolicy2);
                firewallPolicy.Rules.Add(firewallRule);
            }
            finally
            {
                ReleaseComObject(firewallPolicy);
                ReleaseComObject(firewallRule);
            }
        }

        public void RemoveRuleVista(string name, string applicationPath)
        {
            dynamic firewallPolicy = null;

            try
            {
                firewallPolicy = CreateComObject(ProgIdFwPolicy2);

                // Preserve original behavior: remove all rules where (Name == name) OR (ApplicationName == applicationPath)
                var removeRuleNames = new List<string>(2);

                foreach (dynamic rule in firewallPolicy.Rules)
                {
                    try
                    {
                        if (MatchesByNameOrApp(rule, name, applicationPath))
                            removeRuleNames.Add((string)rule.Name);
                    }
                    finally
                    {
                        ReleaseComObject(rule);
                    }
                }

                foreach (string ruleName in removeRuleNames)
                {
                    firewallPolicy.Rules.Remove(ruleName);
                }
            }
            finally
            {
                ReleaseComObject(firewallPolicy);
            }
        }

        public RuleStatus RuleExistsVista(string name, string applicationPath, Protocol protocol)
        {
            dynamic firewallPolicy = null;

            try
            {
                firewallPolicy = CreateComObject(ProgIdFwPolicy2);

                foreach (dynamic rule in firewallPolicy.Rules)
                {
                    try
                    {
                        if (!MatchesByNameOrApp(rule, name, applicationPath))
                            continue;

                        if (protocol != Protocol.Unknown && (int)rule.Protocol != (int)protocol)
                            continue;

                        bool enabled = (bool)rule.Enabled;
                        if (!enabled)
                            return RuleStatus.Disabled;

                        int act = (int)rule.Action;
                        return act == NET_FW_ACTION_ALLOW ? RuleStatus.Allowed : RuleStatus.Blocked;
                    }
                    finally
                    {
                        ReleaseComObject(rule);
                    }
                }

                return RuleStatus.DoesNotExists;
            }
            finally
            {
                ReleaseComObject(firewallPolicy);
            }
        }

        public void AddPort(string name, Protocol protocol, int port, bool enable)
        {
            dynamic portClass = null;
            dynamic firewallManager = null;

            try
            {
                portClass = CreateComObject(ProgIdFwOpenPort);

                portClass.Name = name;
                portClass.Port = port;
                portClass.Scope = NET_FW_SCOPE_ALL;
                portClass.Enabled = enable;

                // Preserve original supported set (UDP/TCP/ANY); throw otherwise.
                portClass.Protocol = ToLegacyPortProtocol(protocol);

                firewallManager = CreateComObject(ProgIdFwMgr);
                firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts.Add(portClass);
            }
            finally
            {
                ReleaseComObject(firewallManager);
                ReleaseComObject(portClass);
            }
        }

        public void RemovePort(Protocol protocol, int port)
        {
            dynamic firewallManager = null;

            try
            {
                firewallManager = CreateComObject(ProgIdFwMgr);
                firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts.Remove(port, ToLegacyPortProtocol(protocol));
            }
            finally
            {
                ReleaseComObject(firewallManager);
            }
        }

        public bool PortExists(Protocol protocol, int port)
        {
            dynamic firewallManager = null;

            try
            {
                int fwProtocol = ToLegacyPortProtocol(protocol);

                firewallManager = CreateComObject(ProgIdFwMgr);
                foreach (dynamic fwPort in firewallManager.LocalPolicy.CurrentProfile.GloballyOpenPorts)
                {
                    try
                    {
                        if ((int)fwPort.Protocol == fwProtocol && (int)fwPort.Port == port)
                            return true;
                    }
                    finally
                    {
                        ReleaseComObject(fwPort);
                    }
                }

                return false;
            }
            finally
            {
                ReleaseComObject(firewallManager);
            }
        }

        public void AddApplication(string name, string path)
        {
            dynamic application = null;
            dynamic firewallManager = null;

            try
            {
                application = CreateComObject(ProgIdFwAuthorizedApplication);

                application.Name = name;
                application.ProcessImageFileName = path;
                application.Enabled = true;

                firewallManager = CreateComObject(ProgIdFwMgr);
                firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications.Add(application);
            }
            finally
            {
                ReleaseComObject(firewallManager);
                ReleaseComObject(application);
            }
        }

        public void RemoveApplication(string path)
        {
            dynamic firewallManager = null;

            try
            {
                firewallManager = CreateComObject(ProgIdFwMgr);
                firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications.Remove(path);
            }
            finally
            {
                ReleaseComObject(firewallManager);
            }
        }

        public RuleStatus ApplicationExists(string path)
        {
            dynamic firewallManager = null;

            try
            {
                firewallManager = CreateComObject(ProgIdFwMgr);

                foreach (dynamic app in firewallManager.LocalPolicy.CurrentProfile.AuthorizedApplications)
                {
                    try
                    {
                        string imagePath = (string)app.ProcessImageFileName;
                        if (imagePath != null && imagePath.Equals(path, StringComparison.OrdinalIgnoreCase))
                        {
                            bool enabled = (bool)app.Enabled;
                            return enabled ? RuleStatus.Allowed : RuleStatus.Disabled;
                        }
                    }
                    finally
                    {
                        ReleaseComObject(app);
                    }
                }

                return RuleStatus.DoesNotExists;
            }
            finally
            {
                ReleaseComObject(firewallManager);
            }
        }

        private static dynamic CreateComObject(string progId)
        {
            var t = Type.GetTypeFromProgID(progId, throwOnError: true);
            return Activator.CreateInstance(t);
        }

        private static void ReleaseComObject(object o)
        {
            if (o == null)
                return;

            try
            {
                if (Marshal.IsComObject(o))
                    Marshal.FinalReleaseComObject(o);
            }
            catch
            {
                // Intentionally swallow to preserve prior behavior (previous code didn't manage COM release).
            }
        }

        private static bool MatchesByNameOrApp(dynamic rule, string name, string applicationPath)
        {
            // Preserve original behavior: match if (Name equals name) OR (ApplicationName equals applicationPath)
            string ruleName = null;
            string ruleApp = null;

            try { ruleName = (string)rule.Name; } catch { /* ignore */ }
            try { ruleApp = (string)rule.ApplicationName; } catch { /* ignore */ }

            if (ruleName != null && ruleName.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;

            if (ruleApp != null && ruleApp.Equals(applicationPath, StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static string InterfaceTypesToString(InterfaceTypeFlags interfaceType)
        {
            if (interfaceType == InterfaceTypeFlags.All)
                return "All";

            string interfaceTypeString = "";

            if ((interfaceType & InterfaceTypeFlags.Lan) > 0)
                interfaceTypeString += ",Lan";

            if ((interfaceType & InterfaceTypeFlags.Wireless) > 0)
                interfaceTypeString += ",Wireless";

            if ((interfaceType & InterfaceTypeFlags.RemoteAccess) > 0)
                interfaceTypeString += ",RemoteAccess";

            if (interfaceTypeString.Length > 0)
                return interfaceTypeString.Substring(1);

            // Preserve original: if nothing matched, leave unset-ish; but COM expects a string.
            return "All";
        }

        private static int ToLegacyPortProtocol(Protocol protocol)
        {
            // Preserve original supported set and exception behavior.
            switch (protocol)
            {
                case Protocol.UDP:
                    return (int)Protocol.UDP;   // 17
                case Protocol.TCP:
                    return (int)Protocol.TCP;   // 6
                case Protocol.ANY:
                    return (int)Protocol.ANY;   // 256
                default:
                    throw new ProtocolViolationException("Protocol not supported.");
            }
        }
    }
}
