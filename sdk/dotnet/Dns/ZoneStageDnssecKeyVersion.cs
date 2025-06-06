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
    /// This resource provides the Zone Stage Dnssec Key Version resource in Oracle Cloud Infrastructure DNS service.
    /// 
    /// Stages a new `DnssecKeyVersion` on the zone. Staging is a process that generates a new "successor" key version
    /// that replaces an existing "predecessor" key version.
    /// **Note:** A new key-signing key (KSK) version is inert until you update the parent zone DS records.
    /// 
    /// For more information, see the [DNSSEC](https://docs.cloud.oracle.com/iaas/Content/DNS/Concepts/dnssec.htm) documentation.
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
    ///     var testZoneStageDnssecKeyVersion = new Oci.Dns.ZoneStageDnssecKeyVersion("test_zone_stage_dnssec_key_version", new()
    ///     {
    ///         PredecessorDnssecKeyVersionUuid = zoneStageDnssecKeyVersionPredecessorDnssecKeyVersionUuid,
    ///         ZoneId = testZone.Id,
    ///         Scope = zoneStageDnssecKeyVersionScope,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Dns/zoneStageDnssecKeyVersion:ZoneStageDnssecKeyVersion")]
    public partial class ZoneStageDnssecKeyVersion : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The UUID of the `DnssecKeyVersion` for which a new successor should be generated.
        /// </summary>
        [Output("predecessorDnssecKeyVersionUuid")]
        public Output<string> PredecessorDnssecKeyVersionUuid { get; private set; } = null!;

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Output("scope")]
        public Output<string> Scope { get; private set; } = null!;

        /// <summary>
        /// The OCID of the target zone.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("zoneId")]
        public Output<string> ZoneId { get; private set; } = null!;


        /// <summary>
        /// Create a ZoneStageDnssecKeyVersion resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ZoneStageDnssecKeyVersion(string name, ZoneStageDnssecKeyVersionArgs args, CustomResourceOptions? options = null)
            : base("oci:Dns/zoneStageDnssecKeyVersion:ZoneStageDnssecKeyVersion", name, args ?? new ZoneStageDnssecKeyVersionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ZoneStageDnssecKeyVersion(string name, Input<string> id, ZoneStageDnssecKeyVersionState? state = null, CustomResourceOptions? options = null)
            : base("oci:Dns/zoneStageDnssecKeyVersion:ZoneStageDnssecKeyVersion", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ZoneStageDnssecKeyVersion resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ZoneStageDnssecKeyVersion Get(string name, Input<string> id, ZoneStageDnssecKeyVersionState? state = null, CustomResourceOptions? options = null)
        {
            return new ZoneStageDnssecKeyVersion(name, id, state, options);
        }
    }

    public sealed class ZoneStageDnssecKeyVersionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The UUID of the `DnssecKeyVersion` for which a new successor should be generated.
        /// </summary>
        [Input("predecessorDnssecKeyVersionUuid", required: true)]
        public Input<string> PredecessorDnssecKeyVersionUuid { get; set; } = null!;

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The OCID of the target zone.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("zoneId", required: true)]
        public Input<string> ZoneId { get; set; } = null!;

        public ZoneStageDnssecKeyVersionArgs()
        {
        }
        public static new ZoneStageDnssecKeyVersionArgs Empty => new ZoneStageDnssecKeyVersionArgs();
    }

    public sealed class ZoneStageDnssecKeyVersionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The UUID of the `DnssecKeyVersion` for which a new successor should be generated.
        /// </summary>
        [Input("predecessorDnssecKeyVersionUuid")]
        public Input<string>? PredecessorDnssecKeyVersionUuid { get; set; }

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The OCID of the target zone.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("zoneId")]
        public Input<string>? ZoneId { get; set; }

        public ZoneStageDnssecKeyVersionState()
        {
        }
        public static new ZoneStageDnssecKeyVersionState Empty => new ZoneStageDnssecKeyVersionState();
    }
}
