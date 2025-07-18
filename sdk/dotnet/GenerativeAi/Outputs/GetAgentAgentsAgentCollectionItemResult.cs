// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Outputs
{

    [OutputType]
    public sealed class GetAgentAgentsAgentCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description about the agent.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// List of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledgeBases associated with agent. This field is deprecated and will be removed after March 26 2026.
        /// </summary>
        public readonly ImmutableArray<string> KnowledgeBaseIds;
        /// <summary>
        /// A message that describes the current state of the agent in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Configuration to Agent LLM.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentsAgentCollectionItemLlmConfigResult> LlmConfigs;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the agent was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the agent was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Details about purpose and responsibility of the agent
        /// </summary>
        public readonly string WelcomeMessage;

        [OutputConstructor]
        private GetAgentAgentsAgentCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<string> knowledgeBaseIds,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetAgentAgentsAgentCollectionItemLlmConfigResult> llmConfigs,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string welcomeMessage)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            KnowledgeBaseIds = knowledgeBaseIds;
            LifecycleDetails = lifecycleDetails;
            LlmConfigs = llmConfigs;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WelcomeMessage = welcomeMessage;
        }
    }
}
