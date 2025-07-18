// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi
{
    /// <summary>
    /// This resource provides the Agent Endpoint resource in Oracle Cloud Infrastructure Generative Ai Agent service.
    /// 
    /// Creates an endpoint.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testAgentEndpoint = new Oci.GenerativeAi.AgentAgentEndpoint("test_agent_endpoint", new()
    ///     {
    ///         AgentId = testAgent.Id,
    ///         CompartmentId = compartmentId,
    ///         ContentModerationConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointContentModerationConfigArgs
    ///         {
    ///             ShouldEnableOnInput = agentEndpointContentModerationConfigShouldEnableOnInput,
    ///             ShouldEnableOnOutput = agentEndpointContentModerationConfigShouldEnableOnOutput,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = agentEndpointDescription,
    ///         DisplayName = agentEndpointDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         GuardrailConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointGuardrailConfigArgs
    ///         {
    ///             ContentModerationConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointGuardrailConfigContentModerationConfigArgs
    ///             {
    ///                 InputGuardrailMode = agentEndpointGuardrailConfigContentModerationConfigInputGuardrailMode,
    ///                 OutputGuardrailMode = agentEndpointGuardrailConfigContentModerationConfigOutputGuardrailMode,
    ///             },
    ///             PersonallyIdentifiableInformationConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointGuardrailConfigPersonallyIdentifiableInformationConfigArgs
    ///             {
    ///                 InputGuardrailMode = agentEndpointGuardrailConfigPersonallyIdentifiableInformationConfigInputGuardrailMode,
    ///                 OutputGuardrailMode = agentEndpointGuardrailConfigPersonallyIdentifiableInformationConfigOutputGuardrailMode,
    ///             },
    ///             PromptInjectionConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointGuardrailConfigPromptInjectionConfigArgs
    ///             {
    ///                 InputGuardrailMode = agentEndpointGuardrailConfigPromptInjectionConfigInputGuardrailMode,
    ///             },
    ///         },
    ///         HumanInputConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointHumanInputConfigArgs
    ///         {
    ///             ShouldEnableHumanInput = agentEndpointHumanInputConfigShouldEnableHumanInput,
    ///         },
    ///         Metadata = agentEndpointMetadata,
    ///         OutputConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointOutputConfigArgs
    ///         {
    ///             OutputLocation = new Oci.GenerativeAi.Inputs.AgentAgentEndpointOutputConfigOutputLocationArgs
    ///             {
    ///                 Bucket = agentEndpointOutputConfigOutputLocationBucket,
    ///                 Namespace = agentEndpointOutputConfigOutputLocationNamespace,
    ///                 OutputLocationType = agentEndpointOutputConfigOutputLocationOutputLocationType,
    ///                 Prefix = agentEndpointOutputConfigOutputLocationPrefix,
    ///             },
    ///             RetentionPeriodInMinutes = agentEndpointOutputConfigRetentionPeriodInMinutes,
    ///         },
    ///         SessionConfig = new Oci.GenerativeAi.Inputs.AgentAgentEndpointSessionConfigArgs
    ///         {
    ///             IdleTimeoutInSeconds = agentEndpointSessionConfigIdleTimeoutInSeconds,
    ///         },
    ///         ShouldEnableCitation = agentEndpointShouldEnableCitation,
    ///         ShouldEnableMultiLanguage = agentEndpointShouldEnableMultiLanguage,
    ///         ShouldEnableSession = agentEndpointShouldEnableSession,
    ///         ShouldEnableTrace = agentEndpointShouldEnableTrace,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// AgentEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:GenerativeAi/agentAgentEndpoint:AgentAgentEndpoint test_agent_endpoint "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:GenerativeAi/agentAgentEndpoint:AgentAgentEndpoint")]
    public partial class AgentAgentEndpoint : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the agent that this endpoint is associated with.
        /// </summary>
        [Output("agentId")]
        public Output<string> AgentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the endpoint in.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
        /// </summary>
        [Output("contentModerationConfig")]
        public Output<Outputs.AgentAgentEndpointContentModerationConfig> ContentModerationConfig { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional description of the endpoint.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the guardrail checks to input and output.
        /// </summary>
        [Output("guardrailConfig")]
        public Output<Outputs.AgentAgentEndpointGuardrailConfig> GuardrailConfig { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Human Input Configuration for an AgentEndpoint.
        /// </summary>
        [Output("humanInputConfig")]
        public Output<Outputs.AgentAgentEndpointHumanInputConfig> HumanInputConfig { get; private set; } = null!;

        /// <summary>
        /// A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Key-value pairs to allow additional configurations.
        /// </summary>
        [Output("metadata")]
        public Output<ImmutableDictionary<string, string>> Metadata { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Configuration to store results generated by agent.
        /// </summary>
        [Output("outputConfig")]
        public Output<Outputs.AgentAgentEndpointOutputConfig> OutputConfig { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Session Configuration on AgentEndpoint.
        /// </summary>
        [Output("sessionConfig")]
        public Output<Outputs.AgentAgentEndpointSessionConfig> SessionConfig { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to show citations in the chat result.
        /// </summary>
        [Output("shouldEnableCitation")]
        public Output<bool> ShouldEnableCitation { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to enable multi-language for chat.
        /// </summary>
        [Output("shouldEnableMultiLanguage")]
        public Output<bool> ShouldEnableMultiLanguage { get; private set; } = null!;

        /// <summary>
        /// Whether or not to enable Session-based chat.
        /// </summary>
        [Output("shouldEnableSession")]
        public Output<bool> ShouldEnableSession { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether to show traces in the chat result.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("shouldEnableTrace")]
        public Output<bool> ShouldEnableTrace { get; private set; } = null!;

        /// <summary>
        /// The current state of the endpoint.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a AgentAgentEndpoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AgentAgentEndpoint(string name, AgentAgentEndpointArgs args, CustomResourceOptions? options = null)
            : base("oci:GenerativeAi/agentAgentEndpoint:AgentAgentEndpoint", name, args ?? new AgentAgentEndpointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AgentAgentEndpoint(string name, Input<string> id, AgentAgentEndpointState? state = null, CustomResourceOptions? options = null)
            : base("oci:GenerativeAi/agentAgentEndpoint:AgentAgentEndpoint", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing AgentAgentEndpoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AgentAgentEndpoint Get(string name, Input<string> id, AgentAgentEndpointState? state = null, CustomResourceOptions? options = null)
        {
            return new AgentAgentEndpoint(name, id, state, options);
        }
    }

    public sealed class AgentAgentEndpointArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the agent that this endpoint is associated with.
        /// </summary>
        [Input("agentId", required: true)]
        public Input<string> AgentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the endpoint in.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
        /// </summary>
        [Input("contentModerationConfig")]
        public Input<Inputs.AgentAgentEndpointContentModerationConfigArgs>? ContentModerationConfig { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) An optional description of the endpoint.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the guardrail checks to input and output.
        /// </summary>
        [Input("guardrailConfig")]
        public Input<Inputs.AgentAgentEndpointGuardrailConfigArgs>? GuardrailConfig { get; set; }

        /// <summary>
        /// (Updatable) Human Input Configuration for an AgentEndpoint.
        /// </summary>
        [Input("humanInputConfig")]
        public Input<Inputs.AgentAgentEndpointHumanInputConfigArgs>? HumanInputConfig { get; set; }

        [Input("metadata")]
        private InputMap<string>? _metadata;

        /// <summary>
        /// (Updatable) Key-value pairs to allow additional configurations.
        /// </summary>
        public InputMap<string> Metadata
        {
            get => _metadata ?? (_metadata = new InputMap<string>());
            set => _metadata = value;
        }

        /// <summary>
        /// (Updatable) Configuration to store results generated by agent.
        /// </summary>
        [Input("outputConfig")]
        public Input<Inputs.AgentAgentEndpointOutputConfigArgs>? OutputConfig { get; set; }

        /// <summary>
        /// (Updatable) Session Configuration on AgentEndpoint.
        /// </summary>
        [Input("sessionConfig")]
        public Input<Inputs.AgentAgentEndpointSessionConfigArgs>? SessionConfig { get; set; }

        /// <summary>
        /// (Updatable) Whether to show citations in the chat result.
        /// </summary>
        [Input("shouldEnableCitation")]
        public Input<bool>? ShouldEnableCitation { get; set; }

        /// <summary>
        /// (Updatable) Whether to enable multi-language for chat.
        /// </summary>
        [Input("shouldEnableMultiLanguage")]
        public Input<bool>? ShouldEnableMultiLanguage { get; set; }

        /// <summary>
        /// Whether or not to enable Session-based chat.
        /// </summary>
        [Input("shouldEnableSession")]
        public Input<bool>? ShouldEnableSession { get; set; }

        /// <summary>
        /// (Updatable) Whether to show traces in the chat result.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("shouldEnableTrace")]
        public Input<bool>? ShouldEnableTrace { get; set; }

        public AgentAgentEndpointArgs()
        {
        }
        public static new AgentAgentEndpointArgs Empty => new AgentAgentEndpointArgs();
    }

    public sealed class AgentAgentEndpointState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the agent that this endpoint is associated with.
        /// </summary>
        [Input("agentId")]
        public Input<string>? AgentId { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to create the endpoint in.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
        /// </summary>
        [Input("contentModerationConfig")]
        public Input<Inputs.AgentAgentEndpointContentModerationConfigGetArgs>? ContentModerationConfig { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) An optional description of the endpoint.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The configuration details about whether to apply the guardrail checks to input and output.
        /// </summary>
        [Input("guardrailConfig")]
        public Input<Inputs.AgentAgentEndpointGuardrailConfigGetArgs>? GuardrailConfig { get; set; }

        /// <summary>
        /// (Updatable) Human Input Configuration for an AgentEndpoint.
        /// </summary>
        [Input("humanInputConfig")]
        public Input<Inputs.AgentAgentEndpointHumanInputConfigGetArgs>? HumanInputConfig { get; set; }

        /// <summary>
        /// A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("metadata")]
        private InputMap<string>? _metadata;

        /// <summary>
        /// (Updatable) Key-value pairs to allow additional configurations.
        /// </summary>
        public InputMap<string> Metadata
        {
            get => _metadata ?? (_metadata = new InputMap<string>());
            set => _metadata = value;
        }

        /// <summary>
        /// (Updatable) Configuration to store results generated by agent.
        /// </summary>
        [Input("outputConfig")]
        public Input<Inputs.AgentAgentEndpointOutputConfigGetArgs>? OutputConfig { get; set; }

        /// <summary>
        /// (Updatable) Session Configuration on AgentEndpoint.
        /// </summary>
        [Input("sessionConfig")]
        public Input<Inputs.AgentAgentEndpointSessionConfigGetArgs>? SessionConfig { get; set; }

        /// <summary>
        /// (Updatable) Whether to show citations in the chat result.
        /// </summary>
        [Input("shouldEnableCitation")]
        public Input<bool>? ShouldEnableCitation { get; set; }

        /// <summary>
        /// (Updatable) Whether to enable multi-language for chat.
        /// </summary>
        [Input("shouldEnableMultiLanguage")]
        public Input<bool>? ShouldEnableMultiLanguage { get; set; }

        /// <summary>
        /// Whether or not to enable Session-based chat.
        /// </summary>
        [Input("shouldEnableSession")]
        public Input<bool>? ShouldEnableSession { get; set; }

        /// <summary>
        /// (Updatable) Whether to show traces in the chat result.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("shouldEnableTrace")]
        public Input<bool>? ShouldEnableTrace { get; set; }

        /// <summary>
        /// The current state of the endpoint.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public AgentAgentEndpointState()
        {
        }
        public static new AgentAgentEndpointState Empty => new AgentAgentEndpointState();
    }
}
