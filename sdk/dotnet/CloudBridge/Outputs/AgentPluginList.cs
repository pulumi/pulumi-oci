// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class AgentPluginList
    {
        /// <summary>
        /// Agent identifier.
        /// </summary>
        public readonly string? AgentId;
        /// <summary>
        /// (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? DefinedTags;
        /// <summary>
        /// (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? FreeformTags;
        /// <summary>
        /// A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string? LifecycleDetails;
        /// <summary>
        /// Plugin identifier, which can be renamed.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// Plugin version.
        /// </summary>
        public readonly string? PluginVersion;
        /// <summary>
        /// The current state of the Agent.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The time when the Agent was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The time when the Agent was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private AgentPluginList(
            string? agentId,

            ImmutableDictionary<string, object>? definedTags,

            ImmutableDictionary<string, object>? freeformTags,

            string? lifecycleDetails,

            string? name,

            string? pluginVersion,

            string? state,

            string? timeCreated,

            string? timeUpdated)
        {
            AgentId = agentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            PluginVersion = pluginVersion;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}