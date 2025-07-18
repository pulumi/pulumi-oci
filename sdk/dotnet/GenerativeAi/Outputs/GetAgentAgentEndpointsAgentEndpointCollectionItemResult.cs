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
    public sealed class GetAgentAgentEndpointsAgentEndpointCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the agent.
        /// </summary>
        public readonly string AgentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemContentModerationConfigResult> ContentModerationConfigs;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// An optional description of the endpoint.
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
        /// The configuration details about whether to apply the guardrail checks to input and output.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemGuardrailConfigResult> GuardrailConfigs;
        /// <summary>
        /// Human Input Configuration for an AgentEndpoint.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemHumanInputConfigResult> HumanInputConfigs;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Key-value pairs to allow additional configurations.
        /// </summary>
        public readonly ImmutableDictionary<string, string> Metadata;
        /// <summary>
        /// Configuration to store results generated by agent.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemOutputConfigResult> OutputConfigs;
        /// <summary>
        /// Session Configuration on AgentEndpoint.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemSessionConfigResult> SessionConfigs;
        /// <summary>
        /// Whether to show citations in the chat result.
        /// </summary>
        public readonly bool ShouldEnableCitation;
        /// <summary>
        /// Whether to enable multi-language for chat.
        /// </summary>
        public readonly bool ShouldEnableMultiLanguage;
        /// <summary>
        /// Whether or not to enable Session-based chat.
        /// </summary>
        public readonly bool ShouldEnableSession;
        /// <summary>
        /// Whether to show traces in the chat result.
        /// </summary>
        public readonly bool ShouldEnableTrace;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetAgentAgentEndpointsAgentEndpointCollectionItemResult(
            string agentId,

            string compartmentId,

            ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemContentModerationConfigResult> contentModerationConfigs,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemGuardrailConfigResult> guardrailConfigs,

            ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemHumanInputConfigResult> humanInputConfigs,

            string id,

            string lifecycleDetails,

            ImmutableDictionary<string, string> metadata,

            ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemOutputConfigResult> outputConfigs,

            ImmutableArray<Outputs.GetAgentAgentEndpointsAgentEndpointCollectionItemSessionConfigResult> sessionConfigs,

            bool shouldEnableCitation,

            bool shouldEnableMultiLanguage,

            bool shouldEnableSession,

            bool shouldEnableTrace,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AgentId = agentId;
            CompartmentId = compartmentId;
            ContentModerationConfigs = contentModerationConfigs;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            GuardrailConfigs = guardrailConfigs;
            HumanInputConfigs = humanInputConfigs;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Metadata = metadata;
            OutputConfigs = outputConfigs;
            SessionConfigs = sessionConfigs;
            ShouldEnableCitation = shouldEnableCitation;
            ShouldEnableMultiLanguage = shouldEnableMultiLanguage;
            ShouldEnableSession = shouldEnableSession;
            ShouldEnableTrace = shouldEnableTrace;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
