// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MediaServices
{
    /// <summary>
    /// This resource provides the Stream Distribution Channel resource in Oracle Cloud Infrastructure Media Services service.
    /// 
    /// Creates a new Stream Distribution Channel.
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
    ///     var testStreamDistributionChannel = new Oci.MediaServices.StreamDistributionChannel("test_stream_distribution_channel", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = streamDistributionChannelDisplayName,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         Locks = new[]
    ///         {
    ///             new Oci.MediaServices.Inputs.StreamDistributionChannelLockArgs
    ///             {
    ///                 CompartmentId = compartmentId,
    ///                 Type = streamDistributionChannelLocksType,
    ///                 Message = streamDistributionChannelLocksMessage,
    ///                 RelatedResourceId = testResource.Id,
    ///                 TimeCreated = streamDistributionChannelLocksTimeCreated,
    ///             },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// StreamDistributionChannels can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:MediaServices/streamDistributionChannel:StreamDistributionChannel test_stream_distribution_channel "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:MediaServices/streamDistributionChannel:StreamDistributionChannel")]
    public partial class StreamDistributionChannel : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Unique domain name of the Distribution Channel.
        /// </summary>
        [Output("domainName")]
        public Output<string> DomainName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        [Output("isLockOverride")]
        public Output<bool> IsLockOverride { get; private set; } = null!;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        [Output("locks")]
        public Output<ImmutableArray<Outputs.StreamDistributionChannelLock>> Locks { get; private set; } = null!;

        /// <summary>
        /// The current state of the Stream Distribution Channel.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a StreamDistributionChannel resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public StreamDistributionChannel(string name, StreamDistributionChannelArgs args, CustomResourceOptions? options = null)
            : base("oci:MediaServices/streamDistributionChannel:StreamDistributionChannel", name, args ?? new StreamDistributionChannelArgs(), MakeResourceOptions(options, ""))
        {
        }

        private StreamDistributionChannel(string name, Input<string> id, StreamDistributionChannelState? state = null, CustomResourceOptions? options = null)
            : base("oci:MediaServices/streamDistributionChannel:StreamDistributionChannel", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing StreamDistributionChannel resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static StreamDistributionChannel Get(string name, Input<string> id, StreamDistributionChannelState? state = null, CustomResourceOptions? options = null)
        {
            return new StreamDistributionChannel(name, id, state, options);
        }
    }

    public sealed class StreamDistributionChannelArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

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

        [Input("isLockOverride")]
        public Input<bool>? IsLockOverride { get; set; }

        [Input("locks")]
        private InputList<Inputs.StreamDistributionChannelLockArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.StreamDistributionChannelLockArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.StreamDistributionChannelLockArgs>());
            set => _locks = value;
        }

        public StreamDistributionChannelArgs()
        {
        }
        public static new StreamDistributionChannelArgs Empty => new StreamDistributionChannelArgs();
    }

    public sealed class StreamDistributionChannelState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Stream Distribution Channel display name. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Unique domain name of the Distribution Channel.
        /// </summary>
        [Input("domainName")]
        public Input<string>? DomainName { get; set; }

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

        [Input("isLockOverride")]
        public Input<bool>? IsLockOverride { get; set; }

        [Input("locks")]
        private InputList<Inputs.StreamDistributionChannelLockGetArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.StreamDistributionChannelLockGetArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.StreamDistributionChannelLockGetArgs>());
            set => _locks = value;
        }

        /// <summary>
        /// The current state of the Stream Distribution Channel.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

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
        /// The time when the Stream Distribution Channel was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the Stream Distribution Channel was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public StreamDistributionChannelState()
        {
        }
        public static new StreamDistributionChannelState Empty => new StreamDistributionChannelState();
    }
}
