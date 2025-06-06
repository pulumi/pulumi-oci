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
    /// This resource provides the Stream Cdn Config resource in Oracle Cloud Infrastructure Media Services service.
    /// 
    /// Creates a new CDN Configuration.
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
    ///     var testStreamCdnConfig = new Oci.MediaServices.StreamCdnConfig("test_stream_cdn_config", new()
    ///     {
    ///         Config = new Oci.MediaServices.Inputs.StreamCdnConfigConfigArgs
    ///         {
    ///             Type = streamCdnConfigConfigType,
    ///             EdgeHostname = streamCdnConfigConfigEdgeHostname,
    ///             EdgePathPrefix = streamCdnConfigConfigEdgePathPrefix,
    ///             EdgeTokenKey = streamCdnConfigConfigEdgeTokenKey,
    ///             EdgeTokenSalt = streamCdnConfigConfigEdgeTokenSalt,
    ///             IsEdgeTokenAuth = streamCdnConfigConfigIsEdgeTokenAuth,
    ///             OriginAuthSecretKeyA = streamCdnConfigConfigOriginAuthSecretKeyA,
    ///             OriginAuthSecretKeyB = streamCdnConfigConfigOriginAuthSecretKeyB,
    ///             OriginAuthSecretKeyNonceA = streamCdnConfigConfigOriginAuthSecretKeyNonceA,
    ///             OriginAuthSecretKeyNonceB = streamCdnConfigConfigOriginAuthSecretKeyNonceB,
    ///             OriginAuthSignEncryption = streamCdnConfigConfigOriginAuthSignEncryption,
    ///             OriginAuthSignType = streamCdnConfigConfigOriginAuthSignType,
    ///         },
    ///         DisplayName = streamCdnConfigDisplayName,
    ///         DistributionChannelId = testChannel.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IsEnabled = streamCdnConfigIsEnabled,
    ///         Locks = new[]
    ///         {
    ///             new Oci.MediaServices.Inputs.StreamCdnConfigLockArgs
    ///             {
    ///                 CompartmentId = compartmentId,
    ///                 Type = streamCdnConfigLocksType,
    ///                 Message = streamCdnConfigLocksMessage,
    ///                 RelatedResourceId = testResource.Id,
    ///                 TimeCreated = streamCdnConfigLocksTimeCreated,
    ///             },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// StreamCdnConfigs can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:MediaServices/streamCdnConfig:StreamCdnConfig test_stream_cdn_config "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:MediaServices/streamCdnConfig:StreamCdnConfig")]
    public partial class StreamCdnConfig : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The compartment ID of the lock.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Base fields of the StreamCdnConfig configuration object.
        /// </summary>
        [Output("config")]
        public Output<Outputs.StreamCdnConfigConfig> Config { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) CDN Config display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Distribution Channel Identifier.
        /// </summary>
        [Output("distributionChannelId")]
        public Output<string> DistributionChannelId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether publishing to CDN is enabled.
        /// </summary>
        [Output("isEnabled")]
        public Output<bool> IsEnabled { get; private set; } = null!;

        [Output("isLockOverride")]
        public Output<bool> IsLockOverride { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecyleDetails")]
        public Output<string> LifecyleDetails { get; private set; } = null!;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        [Output("locks")]
        public Output<ImmutableArray<Outputs.StreamCdnConfigLock>> Locks { get; private set; } = null!;

        /// <summary>
        /// The current state of the CDN Configuration.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when the CDN Config was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the CDN Config was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a StreamCdnConfig resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public StreamCdnConfig(string name, StreamCdnConfigArgs args, CustomResourceOptions? options = null)
            : base("oci:MediaServices/streamCdnConfig:StreamCdnConfig", name, args ?? new StreamCdnConfigArgs(), MakeResourceOptions(options, ""))
        {
        }

        private StreamCdnConfig(string name, Input<string> id, StreamCdnConfigState? state = null, CustomResourceOptions? options = null)
            : base("oci:MediaServices/streamCdnConfig:StreamCdnConfig", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing StreamCdnConfig resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static StreamCdnConfig Get(string name, Input<string> id, StreamCdnConfigState? state = null, CustomResourceOptions? options = null)
        {
            return new StreamCdnConfig(name, id, state, options);
        }
    }

    public sealed class StreamCdnConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Base fields of the StreamCdnConfig configuration object.
        /// </summary>
        [Input("config", required: true)]
        public Input<Inputs.StreamCdnConfigConfigArgs> Config { get; set; } = null!;

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
        /// (Updatable) CDN Config display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// Distribution Channel Identifier.
        /// </summary>
        [Input("distributionChannelId", required: true)]
        public Input<string> DistributionChannelId { get; set; } = null!;

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

        /// <summary>
        /// (Updatable) Whether publishing to CDN is enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        [Input("isLockOverride")]
        public Input<bool>? IsLockOverride { get; set; }

        [Input("locks")]
        private InputList<Inputs.StreamCdnConfigLockArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.StreamCdnConfigLockArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.StreamCdnConfigLockArgs>());
            set => _locks = value;
        }

        public StreamCdnConfigArgs()
        {
        }
        public static new StreamCdnConfigArgs Empty => new StreamCdnConfigArgs();
    }

    public sealed class StreamCdnConfigState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The compartment ID of the lock.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Base fields of the StreamCdnConfig configuration object.
        /// </summary>
        [Input("config")]
        public Input<Inputs.StreamCdnConfigConfigGetArgs>? Config { get; set; }

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
        /// (Updatable) CDN Config display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Distribution Channel Identifier.
        /// </summary>
        [Input("distributionChannelId")]
        public Input<string>? DistributionChannelId { get; set; }

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

        /// <summary>
        /// (Updatable) Whether publishing to CDN is enabled.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        [Input("isLockOverride")]
        public Input<bool>? IsLockOverride { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecyleDetails")]
        public Input<string>? LifecyleDetails { get; set; }

        [Input("locks")]
        private InputList<Inputs.StreamCdnConfigLockGetArgs>? _locks;

        /// <summary>
        /// Locks associated with this resource.
        /// </summary>
        public InputList<Inputs.StreamCdnConfigLockGetArgs> Locks
        {
            get => _locks ?? (_locks = new InputList<Inputs.StreamCdnConfigLockGetArgs>());
            set => _locks = value;
        }

        /// <summary>
        /// The current state of the CDN Configuration.
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
        /// The time when the CDN Config was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the CDN Config was updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public StreamCdnConfigState()
        {
        }
        public static new StreamCdnConfigState Empty => new StreamCdnConfigState();
    }
}
