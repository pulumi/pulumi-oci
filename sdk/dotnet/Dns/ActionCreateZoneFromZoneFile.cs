// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    /// <summary>
    /// This resource provides the Action Create Zone From Zone File resource in Oracle Cloud Infrastructure DNS service.
    /// 
    /// Creates a new zone from a zone file in the specified compartment. Not supported for private zones.
    /// 
    /// After the zone has been created, it should be further managed by importing it to an `oci.Dns.Zone` resource.
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
    ///     var testActionCreateZoneFromZoneFile = new Oci.Dns.ActionCreateZoneFromZoneFile("test_action_create_zone_from_zone_file", new()
    ///     {
    ///         CreateZoneFromZoneFileDetails = actionCreateZoneFromZoneFileCreateZoneFromZoneFileDetails,
    ///         CompartmentId = compartmentId,
    ///         Scope = actionCreateZoneFromZoneFileScope,
    ///         ViewId = testView.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ActionCreateZoneFromZoneFile can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile test_action_create_zone_from_zone_file "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile")]
    public partial class ActionCreateZoneFromZoneFile : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The zone file contents.
        /// </summary>
        [Output("createZoneFromZoneFileDetails")]
        public Output<string> CreateZoneFromZoneFileDetails { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        [Output("dnssecConfigs")]
        public Output<ImmutableArray<Outputs.ActionCreateZoneFromZoneFileDnssecConfig>> DnssecConfigs { get; private set; } = null!;

        [Output("dnssecState")]
        public Output<string> DnssecState { get; private set; } = null!;

        /// <summary>
        /// External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
        /// </summary>
        [Output("externalDownstreams")]
        public Output<ImmutableArray<Outputs.ActionCreateZoneFromZoneFileExternalDownstream>> ExternalDownstreams { get; private set; } = null!;

        /// <summary>
        /// External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        /// </summary>
        [Output("externalMasters")]
        public Output<ImmutableArray<Outputs.ActionCreateZoneFromZoneFileExternalMaster>> ExternalMasters { get; private set; } = null!;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        /// </summary>
        [Output("isProtected")]
        public Output<bool> IsProtected { get; private set; } = null!;

        /// <summary>
        /// The name of the zone.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The authoritative nameservers for the zone.
        /// </summary>
        [Output("nameservers")]
        public Output<ImmutableArray<Outputs.ActionCreateZoneFromZoneFileNameserver>> Nameservers { get; private set; } = null!;

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Output("scope")]
        public Output<string> Scope { get; private set; } = null!;

        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        [Output("self")]
        public Output<string> Self { get; private set; } = null!;

        /// <summary>
        /// The current serial of the zone. As seen in the zone's SOA record.
        /// </summary>
        [Output("serial")]
        public Output<string> Serial { get; private set; } = null!;

        /// <summary>
        /// The current state of the zone resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        /// </summary>
        [Output("version")]
        public Output<string> Version { get; private set; } = null!;

        /// <summary>
        /// The OCID of the view the resource is associated with.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("viewId")]
        public Output<string> ViewId { get; private set; } = null!;

        /// <summary>
        /// The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
        /// </summary>
        [Output("zoneTransferServers")]
        public Output<ImmutableArray<Outputs.ActionCreateZoneFromZoneFileZoneTransferServer>> ZoneTransferServers { get; private set; } = null!;

        /// <summary>
        /// The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        /// </summary>
        [Output("zoneType")]
        public Output<string> ZoneType { get; private set; } = null!;


        /// <summary>
        /// Create a ActionCreateZoneFromZoneFile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ActionCreateZoneFromZoneFile(string name, ActionCreateZoneFromZoneFileArgs args, CustomResourceOptions? options = null)
            : base("oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile", name, args ?? new ActionCreateZoneFromZoneFileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ActionCreateZoneFromZoneFile(string name, Input<string> id, ActionCreateZoneFromZoneFileState? state = null, CustomResourceOptions? options = null)
            : base("oci:Dns/actionCreateZoneFromZoneFile:ActionCreateZoneFromZoneFile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ActionCreateZoneFromZoneFile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ActionCreateZoneFromZoneFile Get(string name, Input<string> id, ActionCreateZoneFromZoneFileState? state = null, CustomResourceOptions? options = null)
        {
            return new ActionCreateZoneFromZoneFile(name, id, state, options);
        }
    }

    public sealed class ActionCreateZoneFromZoneFileArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The zone file contents.
        /// </summary>
        [Input("createZoneFromZoneFileDetails", required: true)]
        public Input<string> CreateZoneFromZoneFileDetails { get; set; } = null!;

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The OCID of the view the resource is associated with.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("viewId")]
        public Input<string>? ViewId { get; set; }

        public ActionCreateZoneFromZoneFileArgs()
        {
        }
        public static new ActionCreateZoneFromZoneFileArgs Empty => new ActionCreateZoneFromZoneFileArgs();
    }

    public sealed class ActionCreateZoneFromZoneFileState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The zone file contents.
        /// </summary>
        [Input("createZoneFromZoneFileDetails")]
        public Input<string>? CreateZoneFromZoneFileDetails { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("dnssecConfigs")]
        private InputList<Inputs.ActionCreateZoneFromZoneFileDnssecConfigGetArgs>? _dnssecConfigs;
        public InputList<Inputs.ActionCreateZoneFromZoneFileDnssecConfigGetArgs> DnssecConfigs
        {
            get => _dnssecConfigs ?? (_dnssecConfigs = new InputList<Inputs.ActionCreateZoneFromZoneFileDnssecConfigGetArgs>());
            set => _dnssecConfigs = value;
        }

        [Input("dnssecState")]
        public Input<string>? DnssecState { get; set; }

        [Input("externalDownstreams")]
        private InputList<Inputs.ActionCreateZoneFromZoneFileExternalDownstreamGetArgs>? _externalDownstreams;

        /// <summary>
        /// External secondary servers for the zone. This field is currently not supported when `zoneType` is `SECONDARY` or `scope` is `PRIVATE`.
        /// </summary>
        public InputList<Inputs.ActionCreateZoneFromZoneFileExternalDownstreamGetArgs> ExternalDownstreams
        {
            get => _externalDownstreams ?? (_externalDownstreams = new InputList<Inputs.ActionCreateZoneFromZoneFileExternalDownstreamGetArgs>());
            set => _externalDownstreams = value;
        }

        [Input("externalMasters")]
        private InputList<Inputs.ActionCreateZoneFromZoneFileExternalMasterGetArgs>? _externalMasters;

        /// <summary>
        /// External master servers for the zone. `externalMasters` becomes a required parameter when the `zoneType` value is `SECONDARY`.
        /// </summary>
        public InputList<Inputs.ActionCreateZoneFromZoneFileExternalMasterGetArgs> ExternalMasters
        {
            get => _externalMasters ?? (_externalMasters = new InputList<Inputs.ActionCreateZoneFromZoneFileExternalMasterGetArgs>());
            set => _externalMasters = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        /// </summary>
        [Input("isProtected")]
        public Input<bool>? IsProtected { get; set; }

        /// <summary>
        /// The name of the zone.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("nameservers")]
        private InputList<Inputs.ActionCreateZoneFromZoneFileNameserverGetArgs>? _nameservers;

        /// <summary>
        /// The authoritative nameservers for the zone.
        /// </summary>
        public InputList<Inputs.ActionCreateZoneFromZoneFileNameserverGetArgs> Nameservers
        {
            get => _nameservers ?? (_nameservers = new InputList<Inputs.ActionCreateZoneFromZoneFileNameserverGetArgs>());
            set => _nameservers = value;
        }

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        [Input("self")]
        public Input<string>? Self { get; set; }

        /// <summary>
        /// The current serial of the zone. As seen in the zone's SOA record.
        /// </summary>
        [Input("serial")]
        public Input<string>? Serial { get; set; }

        /// <summary>
        /// The current state of the zone resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Version is the never-repeating, totally-orderable, version of the zone, from which the serial field of the zone's SOA record is derived.
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        /// <summary>
        /// The OCID of the view the resource is associated with.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("viewId")]
        public Input<string>? ViewId { get; set; }

        [Input("zoneTransferServers")]
        private InputList<Inputs.ActionCreateZoneFromZoneFileZoneTransferServerGetArgs>? _zoneTransferServers;

        /// <summary>
        /// The Oracle Cloud Infrastructure nameservers that transfer the zone data with external nameservers.
        /// </summary>
        public InputList<Inputs.ActionCreateZoneFromZoneFileZoneTransferServerGetArgs> ZoneTransferServers
        {
            get => _zoneTransferServers ?? (_zoneTransferServers = new InputList<Inputs.ActionCreateZoneFromZoneFileZoneTransferServerGetArgs>());
            set => _zoneTransferServers = value;
        }

        /// <summary>
        /// The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        /// </summary>
        [Input("zoneType")]
        public Input<string>? ZoneType { get; set; }

        public ActionCreateZoneFromZoneFileState()
        {
        }
        public static new ActionCreateZoneFromZoneFileState Empty => new ActionCreateZoneFromZoneFileState();
    }
}
