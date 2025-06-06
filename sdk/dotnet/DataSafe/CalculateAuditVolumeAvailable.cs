// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    /// <summary>
    /// This resource provides the Calculate Audit Volume Available resource in Oracle Cloud Infrastructure Data Safe service.
    /// 
    /// Calculates the volume of audit events available on the target database to be collected. Measurable up to the defined retention period of the audit target resource.
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
    ///     var testCalculateAuditVolumeAvailable = new Oci.DataSafe.CalculateAuditVolumeAvailable("test_calculate_audit_volume_available", new()
    ///     {
    ///         AuditProfileId = testAuditProfile.Id,
    ///         AuditCollectionStartTime = calculateAuditVolumeAvailableAuditCollectionStartTime,
    ///         DatabaseUniqueName = calculateAuditVolumeAvailableDatabaseUniqueName,
    ///         TrailLocations = calculateAuditVolumeAvailableTrailLocations,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// CalculateAuditVolumeAvailable can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable test_calculate_audit_volume_available "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable")]
    public partial class CalculateAuditVolumeAvailable : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
        /// </summary>
        [Output("auditCollectionStartTime")]
        public Output<string> AuditCollectionStartTime { get; private set; } = null!;

        /// <summary>
        /// The OCID of the audit.
        /// </summary>
        [Output("auditProfileId")]
        public Output<string> AuditProfileId { get; private set; } = null!;

        /// <summary>
        /// List of available audit volumes.
        /// </summary>
        [Output("availableAuditVolumes")]
        public Output<ImmutableArray<Outputs.CalculateAuditVolumeAvailableAvailableAuditVolume>> AvailableAuditVolumes { get; private set; } = null!;

        /// <summary>
        /// Unique name of the database associated to the peer target database.
        /// </summary>
        [Output("databaseUniqueName")]
        public Output<string> DatabaseUniqueName { get; private set; } = null!;

        /// <summary>
        /// The trail locations for which the audit data volume has to be calculated.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("trailLocations")]
        public Output<ImmutableArray<string>> TrailLocations { get; private set; } = null!;


        /// <summary>
        /// Create a CalculateAuditVolumeAvailable resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public CalculateAuditVolumeAvailable(string name, CalculateAuditVolumeAvailableArgs args, CustomResourceOptions? options = null)
            : base("oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable", name, args ?? new CalculateAuditVolumeAvailableArgs(), MakeResourceOptions(options, ""))
        {
        }

        private CalculateAuditVolumeAvailable(string name, Input<string> id, CalculateAuditVolumeAvailableState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataSafe/calculateAuditVolumeAvailable:CalculateAuditVolumeAvailable", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing CalculateAuditVolumeAvailable resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static CalculateAuditVolumeAvailable Get(string name, Input<string> id, CalculateAuditVolumeAvailableState? state = null, CustomResourceOptions? options = null)
        {
            return new CalculateAuditVolumeAvailable(name, id, state, options);
        }
    }

    public sealed class CalculateAuditVolumeAvailableArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
        /// </summary>
        [Input("auditCollectionStartTime")]
        public Input<string>? AuditCollectionStartTime { get; set; }

        /// <summary>
        /// The OCID of the audit.
        /// </summary>
        [Input("auditProfileId", required: true)]
        public Input<string> AuditProfileId { get; set; } = null!;

        /// <summary>
        /// Unique name of the database associated to the peer target database.
        /// </summary>
        [Input("databaseUniqueName")]
        public Input<string>? DatabaseUniqueName { get; set; }

        [Input("trailLocations")]
        private InputList<string>? _trailLocations;

        /// <summary>
        /// The trail locations for which the audit data volume has to be calculated.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputList<string> TrailLocations
        {
            get => _trailLocations ?? (_trailLocations = new InputList<string>());
            set => _trailLocations = value;
        }

        public CalculateAuditVolumeAvailableArgs()
        {
        }
        public static new CalculateAuditVolumeAvailableArgs Empty => new CalculateAuditVolumeAvailableArgs();
    }

    public sealed class CalculateAuditVolumeAvailableState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The date from which the audit trail must start collecting data in UTC, in the format defined by RFC3339. If not specified, this will default to the date based on the retention period.
        /// </summary>
        [Input("auditCollectionStartTime")]
        public Input<string>? AuditCollectionStartTime { get; set; }

        /// <summary>
        /// The OCID of the audit.
        /// </summary>
        [Input("auditProfileId")]
        public Input<string>? AuditProfileId { get; set; }

        [Input("availableAuditVolumes")]
        private InputList<Inputs.CalculateAuditVolumeAvailableAvailableAuditVolumeGetArgs>? _availableAuditVolumes;

        /// <summary>
        /// List of available audit volumes.
        /// </summary>
        public InputList<Inputs.CalculateAuditVolumeAvailableAvailableAuditVolumeGetArgs> AvailableAuditVolumes
        {
            get => _availableAuditVolumes ?? (_availableAuditVolumes = new InputList<Inputs.CalculateAuditVolumeAvailableAvailableAuditVolumeGetArgs>());
            set => _availableAuditVolumes = value;
        }

        /// <summary>
        /// Unique name of the database associated to the peer target database.
        /// </summary>
        [Input("databaseUniqueName")]
        public Input<string>? DatabaseUniqueName { get; set; }

        [Input("trailLocations")]
        private InputList<string>? _trailLocations;

        /// <summary>
        /// The trail locations for which the audit data volume has to be calculated.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputList<string> TrailLocations
        {
            get => _trailLocations ?? (_trailLocations = new InputList<string>());
            set => _trailLocations = value;
        }

        public CalculateAuditVolumeAvailableState()
        {
        }
        public static new CalculateAuditVolumeAvailableState Empty => new CalculateAuditVolumeAvailableState();
    }
}
