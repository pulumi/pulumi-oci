// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    /// <summary>
    /// This resource provides the Discovery Job resource in Oracle Cloud Infrastructure Stack Monitoring service.
    /// 
    /// API to create discovery Job and submit discovery Details to agent.
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
    ///     var testDiscoveryJob = new Oci.StackMonitoring.DiscoveryJob("test_discovery_job", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DiscoveryDetails = new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsArgs
    ///         {
    ///             AgentId = managementAgentId,
    ///             Properties = new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsPropertiesArgs
    ///             {
    ///                 PropertiesMap = discoveryJobDiscoveryDetailsPropertiesPropertiesMap,
    ///             },
    ///             ResourceName = discoveryJobDiscoveryDetailsResourceName,
    ///             ResourceType = discoveryJobDiscoveryDetailsResourceType,
    ///             Credentials = new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsCredentialsArgs
    ///             {
    ///                 Items = new[]
    ///                 {
    ///                     new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsCredentialsItemArgs
    ///                     {
    ///                         CredentialName = discoveryJobDiscoveryDetailsCredentialsItemsCredentialName,
    ///                         CredentialType = discoveryJobDiscoveryDetailsCredentialsItemsCredentialType,
    ///                         Properties = new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsCredentialsItemPropertiesArgs
    ///                         {
    ///                             PropertiesMap = discoveryJobDiscoveryDetailsCredentialsItemsPropertiesPropertiesMap,
    ///                         },
    ///                     },
    ///                 },
    ///             },
    ///             License = discoveryJobDiscoveryDetailsLicense,
    ///             Tags = new Oci.StackMonitoring.Inputs.DiscoveryJobDiscoveryDetailsTagsArgs
    ///             {
    ///                 PropertiesMap = discoveryJobDiscoveryDetailsTagsPropertiesMap,
    ///             },
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         DiscoveryClient = discoveryJobDiscoveryClient,
    ///         DiscoveryType = discoveryJobDiscoveryType,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         ShouldPropagateTagsToDiscoveredResources = discoveryJobShouldPropagateTagsToDiscoveredResources,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// DiscoveryJobs can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:StackMonitoring/discoveryJob:DiscoveryJob test_discovery_job "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:StackMonitoring/discoveryJob:DiscoveryJob")]
    public partial class DiscoveryJob : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of Compartment
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// Client who submits discovery job.
        /// </summary>
        [Output("discoveryClient")]
        public Output<string> DiscoveryClient { get; private set; } = null!;

        /// <summary>
        /// The request of DiscoveryJob Resource details.
        /// </summary>
        [Output("discoveryDetails")]
        public Output<Outputs.DiscoveryJobDiscoveryDetails> DiscoveryDetails { get; private set; } = null!;

        /// <summary>
        /// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
        /// </summary>
        [Output("discoveryType")]
        public Output<string?> DiscoveryType { get; private set; } = null!;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("shouldPropagateTagsToDiscoveredResources")]
        public Output<bool> ShouldPropagateTagsToDiscoveredResources { get; private set; } = null!;

        /// <summary>
        /// The current state of the DiscoveryJob Resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Specifies the status of the discovery job
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// The short summary of the status of the discovery job
        /// </summary>
        [Output("statusMessage")]
        public Output<string> StatusMessage { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The OCID of Tenant
        /// </summary>
        [Output("tenantId")]
        public Output<string> TenantId { get; private set; } = null!;

        /// <summary>
        /// The time the discovery Job was updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The OCID of user in which the job is submitted
        /// </summary>
        [Output("userId")]
        public Output<string> UserId { get; private set; } = null!;


        /// <summary>
        /// Create a DiscoveryJob resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DiscoveryJob(string name, DiscoveryJobArgs args, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, args ?? new DiscoveryJobArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DiscoveryJob(string name, Input<string> id, DiscoveryJobState? state = null, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/discoveryJob:DiscoveryJob", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DiscoveryJob resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DiscoveryJob Get(string name, Input<string> id, DiscoveryJobState? state = null, CustomResourceOptions? options = null)
        {
            return new DiscoveryJob(name, id, state, options);
        }
    }

    public sealed class DiscoveryJobArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of Compartment
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// Client who submits discovery job.
        /// </summary>
        [Input("discoveryClient")]
        public Input<string>? DiscoveryClient { get; set; }

        /// <summary>
        /// The request of DiscoveryJob Resource details.
        /// </summary>
        [Input("discoveryDetails", required: true)]
        public Input<Inputs.DiscoveryJobDiscoveryDetailsArgs> DiscoveryDetails { get; set; } = null!;

        /// <summary>
        /// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
        /// </summary>
        [Input("discoveryType")]
        public Input<string>? DiscoveryType { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("shouldPropagateTagsToDiscoveredResources")]
        public Input<bool>? ShouldPropagateTagsToDiscoveredResources { get; set; }

        public DiscoveryJobArgs()
        {
        }
        public static new DiscoveryJobArgs Empty => new DiscoveryJobArgs();
    }

    public sealed class DiscoveryJobState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of Compartment
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// Client who submits discovery job.
        /// </summary>
        [Input("discoveryClient")]
        public Input<string>? DiscoveryClient { get; set; }

        /// <summary>
        /// The request of DiscoveryJob Resource details.
        /// </summary>
        [Input("discoveryDetails")]
        public Input<Inputs.DiscoveryJobDiscoveryDetailsGetArgs>? DiscoveryDetails { get; set; }

        /// <summary>
        /// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
        /// </summary>
        [Input("discoveryType")]
        public Input<string>? DiscoveryType { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// If this parameter set to true, the specified tags will be applied  to all resources discovered in the current request.  Default is true. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("shouldPropagateTagsToDiscoveredResources")]
        public Input<bool>? ShouldPropagateTagsToDiscoveredResources { get; set; }

        /// <summary>
        /// The current state of the DiscoveryJob Resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Specifies the status of the discovery job
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// The short summary of the status of the discovery job
        /// </summary>
        [Input("statusMessage")]
        public Input<string>? StatusMessage { get; set; }

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
        /// The OCID of Tenant
        /// </summary>
        [Input("tenantId")]
        public Input<string>? TenantId { get; set; }

        /// <summary>
        /// The time the discovery Job was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The OCID of user in which the job is submitted
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public DiscoveryJobState()
        {
        }
        public static new DiscoveryJobState Empty => new DiscoveryJobState();
    }
}
