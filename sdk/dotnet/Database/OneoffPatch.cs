// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Oneoff Patch resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates one-off patch for specified database version to download.
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
    ///     var testOneoffPatch = new Oci.Database.OneoffPatch("testOneoffPatch", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         DbVersion = @var.Oneoff_patch_db_version,
    ///         DisplayName = @var.Oneoff_patch_display_name,
    ///         ReleaseUpdate = @var.Oneoff_patch_release_update,
    ///         DefinedTags = @var.Oneoff_patch_defined_tags,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         OneOffPatches = @var.Oneoff_patch_one_off_patches,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OneoffPatches can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Database/oneoffPatch:OneoffPatch test_oneoff_patch "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/oneoffPatch:OneoffPatch")]
    public partial class OneoffPatch : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Output("dbVersion")]
        public Output<string> DbVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// One-off patch name.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Download Oneoff Patch. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("downloadOneoffPatchTrigger")]
        public Output<int?> DownloadOneoffPatchTrigger { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Detailed message for the lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// List of one-off patches for Database Homes.
        /// </summary>
        [Output("oneOffPatches")]
        public Output<ImmutableArray<string>> OneOffPatches { get; private set; } = null!;

        /// <summary>
        /// The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Output("releaseUpdate")]
        public Output<string> ReleaseUpdate { get; private set; } = null!;

        /// <summary>
        /// SHA-256 checksum of the one-off patch.
        /// </summary>
        [Output("sha256sum")]
        public Output<string> Sha256sum { get; private set; } = null!;

        /// <summary>
        /// The size of one-off patch in kilobytes.
        /// </summary>
        [Output("sizeInKbs")]
        public Output<double> SizeInKbs { get; private set; } = null!;

        /// <summary>
        /// The current state of the one-off patch.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time one-off patch was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time until which the one-off patch will be available for download.
        /// </summary>
        [Output("timeOfExpiration")]
        public Output<string> TimeOfExpiration { get; private set; } = null!;

        /// <summary>
        /// The date and time one-off patch was updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a OneoffPatch resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OneoffPatch(string name, OneoffPatchArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/oneoffPatch:OneoffPatch", name, args ?? new OneoffPatchArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OneoffPatch(string name, Input<string> id, OneoffPatchState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/oneoffPatch:OneoffPatch", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OneoffPatch resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OneoffPatch Get(string name, Input<string> id, OneoffPatchState? state = null, CustomResourceOptions? options = null)
        {
            return new OneoffPatch(name, id, state, options);
        }
    }

    public sealed class OneoffPatchArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion", required: true)]
        public Input<string> DbVersion { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// One-off patch name.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Download Oneoff Patch. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("downloadOneoffPatchTrigger")]
        public Input<int>? DownloadOneoffPatchTrigger { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("oneOffPatches")]
        private InputList<string>? _oneOffPatches;

        /// <summary>
        /// List of one-off patches for Database Homes.
        /// </summary>
        public InputList<string> OneOffPatches
        {
            get => _oneOffPatches ?? (_oneOffPatches = new InputList<string>());
            set => _oneOffPatches = value;
        }

        /// <summary>
        /// The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("releaseUpdate", required: true)]
        public Input<string> ReleaseUpdate { get; set; } = null!;

        public OneoffPatchArgs()
        {
        }
        public static new OneoffPatchArgs Empty => new OneoffPatchArgs();
    }

    public sealed class OneoffPatchState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion")]
        public Input<string>? DbVersion { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// One-off patch name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) An optional property when incremented triggers Download Oneoff Patch. Could be set to any integer value.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("downloadOneoffPatchTrigger")]
        public Input<int>? DownloadOneoffPatchTrigger { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Detailed message for the lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        [Input("oneOffPatches")]
        private InputList<string>? _oneOffPatches;

        /// <summary>
        /// List of one-off patches for Database Homes.
        /// </summary>
        public InputList<string> OneOffPatches
        {
            get => _oneOffPatches ?? (_oneOffPatches = new InputList<string>());
            set => _oneOffPatches = value;
        }

        /// <summary>
        /// The PSU or PBP or Release Updates. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("releaseUpdate")]
        public Input<string>? ReleaseUpdate { get; set; }

        /// <summary>
        /// SHA-256 checksum of the one-off patch.
        /// </summary>
        [Input("sha256sum")]
        public Input<string>? Sha256sum { get; set; }

        /// <summary>
        /// The size of one-off patch in kilobytes.
        /// </summary>
        [Input("sizeInKbs")]
        public Input<double>? SizeInKbs { get; set; }

        /// <summary>
        /// The current state of the one-off patch.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time one-off patch was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time until which the one-off patch will be available for download.
        /// </summary>
        [Input("timeOfExpiration")]
        public Input<string>? TimeOfExpiration { get; set; }

        /// <summary>
        /// The date and time one-off patch was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public OneoffPatchState()
        {
        }
        public static new OneoffPatchState Empty => new OneoffPatchState();
    }
}