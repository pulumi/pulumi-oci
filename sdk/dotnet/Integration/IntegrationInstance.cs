// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration
{
    /// <summary>
    /// This resource provides the Integration Instance resource in Oracle Cloud Infrastructure Integration service.
    /// 
    /// Creates a new Integration Instance.
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
    ///     var testIntegrationInstance = new Oci.Integration.IntegrationInstance("test_integration_instance", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = integrationInstanceDisplayName,
    ///         IntegrationInstanceType = integrationInstanceIntegrationInstanceType,
    ///         IsByol = integrationInstanceIsByol,
    ///         MessagePacks = integrationInstanceMessagePacks,
    ///         AlternateCustomEndpoints = new[]
    ///         {
    ///             new Oci.Integration.Inputs.IntegrationInstanceAlternateCustomEndpointArgs
    ///             {
    ///                 Hostname = integrationInstanceAlternateCustomEndpointsHostname,
    ///                 CertificateSecretId = testSecret.Id,
    ///             },
    ///         },
    ///         ConsumptionModel = integrationInstanceConsumptionModel,
    ///         CustomEndpoint = new Oci.Integration.Inputs.IntegrationInstanceCustomEndpointArgs
    ///         {
    ///             Hostname = integrationInstanceCustomEndpointHostname,
    ///             CertificateSecretId = testSecret.Id,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         DomainId = testDomain.Id,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IdcsAt = integrationInstanceIdcsAt,
    ///         IsDisasterRecoveryEnabled = integrationInstanceIsDisasterRecoveryEnabled,
    ///         IsFileServerEnabled = integrationInstanceIsFileServerEnabled,
    ///         IsVisualBuilderEnabled = integrationInstanceIsVisualBuilderEnabled,
    ///         NetworkEndpointDetails = new Oci.Integration.Inputs.IntegrationInstanceNetworkEndpointDetailsArgs
    ///         {
    ///             NetworkEndpointType = integrationInstanceNetworkEndpointDetailsNetworkEndpointType,
    ///             AllowlistedHttpIps = integrationInstanceNetworkEndpointDetailsAllowlistedHttpIps,
    ///             AllowlistedHttpVcns = new[]
    ///             {
    ///                 new Oci.Integration.Inputs.IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnArgs
    ///                 {
    ///                     Id = integrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnsId,
    ///                     AllowlistedIps = integrationInstanceNetworkEndpointDetailsAllowlistedHttpVcnsAllowlistedIps,
    ///                 },
    ///             },
    ///             IsIntegrationVcnAllowlisted = integrationInstanceNetworkEndpointDetailsIsIntegrationVcnAllowlisted,
    ///         },
    ///         Shape = integrationInstanceShape,
    ///         State = integrationInstanceTargetState,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// IntegrationInstances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Integration/integrationInstance:IntegrationInstance test_integration_instance "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Integration/integrationInstance:IntegrationInstance")]
    public partial class IntegrationInstance : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) A list of alternate custom endpoints to be used for the integration instance URL (contact Oracle for alternateCustomEndpoints availability for a specific instance).
        /// </summary>
        [Output("alternateCustomEndpoints")]
        public Output<ImmutableArray<Outputs.IntegrationInstanceAlternateCustomEndpoint>> AlternateCustomEndpoints { get; private set; } = null!;

        /// <summary>
        /// A list of associated attachments to other services
        /// </summary>
        [Output("attachments")]
        public Output<ImmutableArray<Outputs.IntegrationInstanceAttachment>> Attachments { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Optional parameter specifying which entitlement to use for billing purposes. Only required if the account possesses more than one entitlement.
        /// </summary>
        [Output("consumptionModel")]
        public Output<string> ConsumptionModel { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details for a custom endpoint for the integration instance (update).
        /// </summary>
        [Output("customEndpoint")]
        public Output<Outputs.IntegrationInstanceCustomEndpoint> CustomEndpoint { get; private set; } = null!;

        /// <summary>
        /// Data retention period set for given integration instance
        /// </summary>
        [Output("dataRetentionPeriod")]
        public Output<string> DataRetentionPeriod { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// Disaster recovery details for the integration instance created in the region.
        /// </summary>
        [Output("disasterRecoveryDetails")]
        public Output<ImmutableArray<Outputs.IntegrationInstanceDisasterRecoveryDetail>> DisasterRecoveryDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Integration Instance Identifier.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The OCID of the identity domain, that will be used to determine the  corresponding Idcs Stripe and create an Idcs application within the stripe.  This parameter is mutually exclusive with parameter: idcsAt, i.e only one of  two parameters should be specified.
        /// </summary>
        [Output("domainId")]
        public Output<string?> DomainId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Enable Process Automation. Could be set to any integer value.
        /// </summary>
        [Output("enableProcessAutomationTrigger")]
        public Output<int?> EnableProcessAutomationTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Extend Data Retention. Could be set to any integer value.
        /// </summary>
        [Output("extendDataRetentionTrigger")]
        public Output<int?> ExtendDataRetentionTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Failover. Could be set to any integer value.
        /// </summary>
        [Output("failoverTrigger")]
        public Output<int?> FailoverTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) IDCS Authentication token. This is required for all realms with IDCS. Its optional as its not required for non IDCS realms.
        /// </summary>
        [Output("idcsAt")]
        public Output<string?> IdcsAt { get; private set; } = null!;

        /// <summary>
        /// Information for IDCS access
        /// </summary>
        [Output("idcsInfos")]
        public Output<ImmutableArray<Outputs.IntegrationInstanceIdcsInfo>> IdcsInfos { get; private set; } = null!;

        [Output("instanceDesignTimeUrl")]
        public Output<string> InstanceDesignTimeUrl { get; private set; } = null!;

        /// <summary>
        /// The Integration Instance URL.
        /// </summary>
        [Output("instanceUrl")]
        public Output<string> InstanceUrl { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Standard or Enterprise type,  Oracle Integration Generation 2 uses ENTERPRISE and STANDARD,  Oracle Integration 3 uses ENTERPRISEX and STANDARDX
        /// </summary>
        [Output("integrationInstanceType")]
        public Output<string> IntegrationInstanceType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Bring your own license.
        /// </summary>
        [Output("isByol")]
        public Output<bool> IsByol { get; private set; } = null!;

        /// <summary>
        /// Is Disaster Recovery enabled or not.
        /// </summary>
        [Output("isDisasterRecoveryEnabled")]
        public Output<bool> IsDisasterRecoveryEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The file server is enabled or not.
        /// </summary>
        [Output("isFileServerEnabled")]
        public Output<bool> IsFileServerEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Visual Builder is enabled or not.
        /// </summary>
        [Output("isVisualBuilderEnabled")]
        public Output<bool> IsVisualBuilderEnabled { get; private set; } = null!;

        /// <summary>
        /// Additional details of lifecycleState or substates
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The number of configured message packs
        /// </summary>
        [Output("messagePacks")]
        public Output<int> MessagePacks { get; private set; } = null!;

        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        [Output("networkEndpointDetails")]
        public Output<Outputs.IntegrationInstanceNetworkEndpointDetails> NetworkEndpointDetails { get; private set; } = null!;

        /// <summary>
        /// Base representation for Outbound Connection (Reverse Connection).
        /// </summary>
        [Output("privateEndpointOutboundConnections")]
        public Output<ImmutableArray<Outputs.IntegrationInstancePrivateEndpointOutboundConnection>> PrivateEndpointOutboundConnections { get; private set; } = null!;

        /// <summary>
        /// Shape
        /// </summary>
        [Output("shape")]
        public Output<string> Shape { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The target state for the instance. Could be set to ACTIVE or INACTIVE
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("stateMessage")]
        public Output<string> StateMessage { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a IntegrationInstance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IntegrationInstance(string name, IntegrationInstanceArgs args, CustomResourceOptions? options = null)
            : base("oci:Integration/integrationInstance:IntegrationInstance", name, args ?? new IntegrationInstanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IntegrationInstance(string name, Input<string> id, IntegrationInstanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:Integration/integrationInstance:IntegrationInstance", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                AdditionalSecretOutputs =
                {
                    "idcsAt",
                },
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing IntegrationInstance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IntegrationInstance Get(string name, Input<string> id, IntegrationInstanceState? state = null, CustomResourceOptions? options = null)
        {
            return new IntegrationInstance(name, id, state, options);
        }
    }

    public sealed class IntegrationInstanceArgs : global::Pulumi.ResourceArgs
    {
        [Input("alternateCustomEndpoints")]
        private InputList<Inputs.IntegrationInstanceAlternateCustomEndpointArgs>? _alternateCustomEndpoints;

        /// <summary>
        /// (Updatable) A list of alternate custom endpoints to be used for the integration instance URL (contact Oracle for alternateCustomEndpoints availability for a specific instance).
        /// </summary>
        public InputList<Inputs.IntegrationInstanceAlternateCustomEndpointArgs> AlternateCustomEndpoints
        {
            get => _alternateCustomEndpoints ?? (_alternateCustomEndpoints = new InputList<Inputs.IntegrationInstanceAlternateCustomEndpointArgs>());
            set => _alternateCustomEndpoints = value;
        }

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Optional parameter specifying which entitlement to use for billing purposes. Only required if the account possesses more than one entitlement.
        /// </summary>
        [Input("consumptionModel")]
        public Input<string>? ConsumptionModel { get; set; }

        /// <summary>
        /// (Updatable) Details for a custom endpoint for the integration instance (update).
        /// </summary>
        [Input("customEndpoint")]
        public Input<Inputs.IntegrationInstanceCustomEndpointArgs>? CustomEndpoint { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Integration Instance Identifier.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// The OCID of the identity domain, that will be used to determine the  corresponding Idcs Stripe and create an Idcs application within the stripe.  This parameter is mutually exclusive with parameter: idcsAt, i.e only one of  two parameters should be specified.
        /// </summary>
        [Input("domainId")]
        public Input<string>? DomainId { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Enable Process Automation. Could be set to any integer value.
        /// </summary>
        [Input("enableProcessAutomationTrigger")]
        public Input<int>? EnableProcessAutomationTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Extend Data Retention. Could be set to any integer value.
        /// </summary>
        [Input("extendDataRetentionTrigger")]
        public Input<int>? ExtendDataRetentionTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Failover. Could be set to any integer value.
        /// </summary>
        [Input("failoverTrigger")]
        public Input<int>? FailoverTrigger { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        [Input("idcsAt")]
        private Input<string>? _idcsAt;

        /// <summary>
        /// (Updatable) IDCS Authentication token. This is required for all realms with IDCS. Its optional as its not required for non IDCS realms.
        /// </summary>
        public Input<string>? IdcsAt
        {
            get => _idcsAt;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _idcsAt = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// (Updatable) Standard or Enterprise type,  Oracle Integration Generation 2 uses ENTERPRISE and STANDARD,  Oracle Integration 3 uses ENTERPRISEX and STANDARDX
        /// </summary>
        [Input("integrationInstanceType", required: true)]
        public Input<string> IntegrationInstanceType { get; set; } = null!;

        /// <summary>
        /// (Updatable) Bring your own license.
        /// </summary>
        [Input("isByol", required: true)]
        public Input<bool> IsByol { get; set; } = null!;

        /// <summary>
        /// Is Disaster Recovery enabled or not.
        /// </summary>
        [Input("isDisasterRecoveryEnabled")]
        public Input<bool>? IsDisasterRecoveryEnabled { get; set; }

        /// <summary>
        /// (Updatable) The file server is enabled or not.
        /// </summary>
        [Input("isFileServerEnabled")]
        public Input<bool>? IsFileServerEnabled { get; set; }

        /// <summary>
        /// (Updatable) Visual Builder is enabled or not.
        /// </summary>
        [Input("isVisualBuilderEnabled")]
        public Input<bool>? IsVisualBuilderEnabled { get; set; }

        /// <summary>
        /// (Updatable) The number of configured message packs
        /// </summary>
        [Input("messagePacks", required: true)]
        public Input<int> MessagePacks { get; set; } = null!;

        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        [Input("networkEndpointDetails")]
        public Input<Inputs.IntegrationInstanceNetworkEndpointDetailsArgs>? NetworkEndpointDetails { get; set; }

        /// <summary>
        /// Shape
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// (Updatable) The target state for the instance. Could be set to ACTIVE or INACTIVE
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public IntegrationInstanceArgs()
        {
        }
        public static new IntegrationInstanceArgs Empty => new IntegrationInstanceArgs();
    }

    public sealed class IntegrationInstanceState : global::Pulumi.ResourceArgs
    {
        [Input("alternateCustomEndpoints")]
        private InputList<Inputs.IntegrationInstanceAlternateCustomEndpointGetArgs>? _alternateCustomEndpoints;

        /// <summary>
        /// (Updatable) A list of alternate custom endpoints to be used for the integration instance URL (contact Oracle for alternateCustomEndpoints availability for a specific instance).
        /// </summary>
        public InputList<Inputs.IntegrationInstanceAlternateCustomEndpointGetArgs> AlternateCustomEndpoints
        {
            get => _alternateCustomEndpoints ?? (_alternateCustomEndpoints = new InputList<Inputs.IntegrationInstanceAlternateCustomEndpointGetArgs>());
            set => _alternateCustomEndpoints = value;
        }

        [Input("attachments")]
        private InputList<Inputs.IntegrationInstanceAttachmentGetArgs>? _attachments;

        /// <summary>
        /// A list of associated attachments to other services
        /// </summary>
        public InputList<Inputs.IntegrationInstanceAttachmentGetArgs> Attachments
        {
            get => _attachments ?? (_attachments = new InputList<Inputs.IntegrationInstanceAttachmentGetArgs>());
            set => _attachments = value;
        }

        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Optional parameter specifying which entitlement to use for billing purposes. Only required if the account possesses more than one entitlement.
        /// </summary>
        [Input("consumptionModel")]
        public Input<string>? ConsumptionModel { get; set; }

        /// <summary>
        /// (Updatable) Details for a custom endpoint for the integration instance (update).
        /// </summary>
        [Input("customEndpoint")]
        public Input<Inputs.IntegrationInstanceCustomEndpointGetArgs>? CustomEndpoint { get; set; }

        /// <summary>
        /// Data retention period set for given integration instance
        /// </summary>
        [Input("dataRetentionPeriod")]
        public Input<string>? DataRetentionPeriod { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("disasterRecoveryDetails")]
        private InputList<Inputs.IntegrationInstanceDisasterRecoveryDetailGetArgs>? _disasterRecoveryDetails;

        /// <summary>
        /// Disaster recovery details for the integration instance created in the region.
        /// </summary>
        public InputList<Inputs.IntegrationInstanceDisasterRecoveryDetailGetArgs> DisasterRecoveryDetails
        {
            get => _disasterRecoveryDetails ?? (_disasterRecoveryDetails = new InputList<Inputs.IntegrationInstanceDisasterRecoveryDetailGetArgs>());
            set => _disasterRecoveryDetails = value;
        }

        /// <summary>
        /// (Updatable) Integration Instance Identifier.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The OCID of the identity domain, that will be used to determine the  corresponding Idcs Stripe and create an Idcs application within the stripe.  This parameter is mutually exclusive with parameter: idcsAt, i.e only one of  two parameters should be specified.
        /// </summary>
        [Input("domainId")]
        public Input<string>? DomainId { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Enable Process Automation. Could be set to any integer value.
        /// </summary>
        [Input("enableProcessAutomationTrigger")]
        public Input<int>? EnableProcessAutomationTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Extend Data Retention. Could be set to any integer value.
        /// </summary>
        [Input("extendDataRetentionTrigger")]
        public Input<int>? ExtendDataRetentionTrigger { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Failover. Could be set to any integer value.
        /// </summary>
        [Input("failoverTrigger")]
        public Input<int>? FailoverTrigger { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        [Input("idcsAt")]
        private Input<string>? _idcsAt;

        /// <summary>
        /// (Updatable) IDCS Authentication token. This is required for all realms with IDCS. Its optional as its not required for non IDCS realms.
        /// </summary>
        public Input<string>? IdcsAt
        {
            get => _idcsAt;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _idcsAt = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        [Input("idcsInfos")]
        private InputList<Inputs.IntegrationInstanceIdcsInfoGetArgs>? _idcsInfos;

        /// <summary>
        /// Information for IDCS access
        /// </summary>
        public InputList<Inputs.IntegrationInstanceIdcsInfoGetArgs> IdcsInfos
        {
            get => _idcsInfos ?? (_idcsInfos = new InputList<Inputs.IntegrationInstanceIdcsInfoGetArgs>());
            set => _idcsInfos = value;
        }

        [Input("instanceDesignTimeUrl")]
        public Input<string>? InstanceDesignTimeUrl { get; set; }

        /// <summary>
        /// The Integration Instance URL.
        /// </summary>
        [Input("instanceUrl")]
        public Input<string>? InstanceUrl { get; set; }

        /// <summary>
        /// (Updatable) Standard or Enterprise type,  Oracle Integration Generation 2 uses ENTERPRISE and STANDARD,  Oracle Integration 3 uses ENTERPRISEX and STANDARDX
        /// </summary>
        [Input("integrationInstanceType")]
        public Input<string>? IntegrationInstanceType { get; set; }

        /// <summary>
        /// (Updatable) Bring your own license.
        /// </summary>
        [Input("isByol")]
        public Input<bool>? IsByol { get; set; }

        /// <summary>
        /// Is Disaster Recovery enabled or not.
        /// </summary>
        [Input("isDisasterRecoveryEnabled")]
        public Input<bool>? IsDisasterRecoveryEnabled { get; set; }

        /// <summary>
        /// (Updatable) The file server is enabled or not.
        /// </summary>
        [Input("isFileServerEnabled")]
        public Input<bool>? IsFileServerEnabled { get; set; }

        /// <summary>
        /// (Updatable) Visual Builder is enabled or not.
        /// </summary>
        [Input("isVisualBuilderEnabled")]
        public Input<bool>? IsVisualBuilderEnabled { get; set; }

        /// <summary>
        /// Additional details of lifecycleState or substates
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) The number of configured message packs
        /// </summary>
        [Input("messagePacks")]
        public Input<int>? MessagePacks { get; set; }

        /// <summary>
        /// Base representation of a network endpoint.
        /// </summary>
        [Input("networkEndpointDetails")]
        public Input<Inputs.IntegrationInstanceNetworkEndpointDetailsGetArgs>? NetworkEndpointDetails { get; set; }

        [Input("privateEndpointOutboundConnections")]
        private InputList<Inputs.IntegrationInstancePrivateEndpointOutboundConnectionGetArgs>? _privateEndpointOutboundConnections;

        /// <summary>
        /// Base representation for Outbound Connection (Reverse Connection).
        /// </summary>
        public InputList<Inputs.IntegrationInstancePrivateEndpointOutboundConnectionGetArgs> PrivateEndpointOutboundConnections
        {
            get => _privateEndpointOutboundConnections ?? (_privateEndpointOutboundConnections = new InputList<Inputs.IntegrationInstancePrivateEndpointOutboundConnectionGetArgs>());
            set => _privateEndpointOutboundConnections = value;
        }

        /// <summary>
        /// Shape
        /// </summary>
        [Input("shape")]
        public Input<string>? Shape { get; set; }

        /// <summary>
        /// (Updatable) The target state for the instance. Could be set to ACTIVE or INACTIVE
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// An message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("stateMessage")]
        public Input<string>? StateMessage { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the the Integration Instance was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the IntegrationInstance was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public IntegrationInstanceState()
        {
        }
        public static new IntegrationInstanceState Empty => new IntegrationInstanceState();
    }
}
