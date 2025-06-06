// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    /// <summary>
    /// This resource provides the Profile resource in Oracle Cloud Infrastructure Os Management Hub service.
    /// 
    /// Creates a registration profile. A profile defines the content applied to the instance when registering it with the service.
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
    ///     var testProfile = new Oci.OsManagementHub.Profile("test_profile", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DisplayName = profileDisplayName,
    ///         ProfileType = profileProfileType,
    ///         ArchType = profileArchType,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         Description = profileDescription,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         IsDefaultProfile = profileIsDefaultProfile,
    ///         LifecycleStageId = testLifecycleStage.Id,
    ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
    ///         ManagementStationId = testManagementStation.Id,
    ///         OsFamily = profileOsFamily,
    ///         RegistrationType = profileRegistrationType,
    ///         SoftwareSourceIds = profileSoftwareSourceIds,
    ///         VendorName = profileVendorName,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Profiles can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagementHub/profile:Profile test_profile "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagementHub/profile:Profile")]
    public partial class Profile : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The architecture type.
        /// </summary>
        [Output("archType")]
        public Output<string> ArchType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the registration profile.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) User-specified description of the registration profile.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique and you can change the name later. Avoid entering  confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.
        /// </summary>
        [Output("isDefaultProfile")]
        public Output<bool> IsDefaultProfile { get; private set; } = null!;

        /// <summary>
        /// Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.
        /// </summary>
        [Output("isServiceProvidedProfile")]
        public Output<bool> IsServiceProvidedProfile { get; private set; } = null!;

        /// <summary>
        /// Provides identifying information for the specified lifecycle environment.
        /// </summary>
        [Output("lifecycleEnvironments")]
        public Output<ImmutableArray<Outputs.ProfileLifecycleEnvironment>> LifecycleEnvironments { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Output("lifecycleStageId")]
        public Output<string> LifecycleStageId { get; private set; } = null!;

        /// <summary>
        /// Provides identifying information for the specified lifecycle stage.
        /// </summary>
        [Output("lifecycleStages")]
        public Output<ImmutableArray<Outputs.ProfileLifecycleStage>> LifecycleStages { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group that the instance will join after registration.
        /// </summary>
        [Output("managedInstanceGroupId")]
        public Output<string> ManagedInstanceGroupId { get; private set; } = null!;

        /// <summary>
        /// Provides identifying information for the specified managed instance group.
        /// </summary>
        [Output("managedInstanceGroups")]
        public Output<ImmutableArray<Outputs.ProfileManagedInstanceGroup>> ManagedInstanceGroups { get; private set; } = null!;

        /// <summary>
        /// description: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station to associate  with an instance once registered. This is required when creating a profile for non-OCI instances.
        /// </summary>
        [Output("managementStationId")]
        public Output<string> ManagementStationId { get; private set; } = null!;

        /// <summary>
        /// The operating system family.
        /// </summary>
        [Output("osFamily")]
        public Output<string> OsFamily { get; private set; } = null!;

        /// <summary>
        /// The type of profile.
        /// </summary>
        [Output("profileType")]
        public Output<string> ProfileType { get; private set; } = null!;

        /// <summary>
        /// The version of the profile. The version is automatically incremented each time the profiled is edited.
        /// </summary>
        [Output("profileVersion")]
        public Output<string> ProfileVersion { get; private set; } = null!;

        /// <summary>
        /// The type of instance to register.
        /// </summary>
        [Output("registrationType")]
        public Output<string> RegistrationType { get; private set; } = null!;

        /// <summary>
        /// The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the registration profile will use.
        /// </summary>
        [Output("softwareSourceIds")]
        public Output<ImmutableArray<string>> SoftwareSourceIds { get; private set; } = null!;

        /// <summary>
        /// The list of software sources that the registration profile will use.
        /// </summary>
        [Output("softwareSources")]
        public Output<ImmutableArray<Outputs.ProfileSoftwareSource>> SoftwareSources { get; private set; } = null!;

        /// <summary>
        /// The current state of the registration profile.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time the registration profile was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the registration profile was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        [Output("timeModified")]
        public Output<string> TimeModified { get; private set; } = null!;

        /// <summary>
        /// The vendor of the operating system for the instance.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("vendorName")]
        public Output<string> VendorName { get; private set; } = null!;


        /// <summary>
        /// Create a Profile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Profile(string name, ProfileArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/profile:Profile", name, args ?? new ProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Profile(string name, Input<string> id, ProfileState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/profile:Profile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Profile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Profile Get(string name, Input<string> id, ProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new Profile(name, id, state, options);
        }
    }

    public sealed class ProfileArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The architecture type.
        /// </summary>
        [Input("archType")]
        public Input<string>? ArchType { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the registration profile.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) User-specified description of the registration profile.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique and you can change the name later. Avoid entering  confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.
        /// </summary>
        [Input("isDefaultProfile")]
        public Input<bool>? IsDefaultProfile { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Input("lifecycleStageId")]
        public Input<string>? LifecycleStageId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group that the instance will join after registration.
        /// </summary>
        [Input("managedInstanceGroupId")]
        public Input<string>? ManagedInstanceGroupId { get; set; }

        /// <summary>
        /// description: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station to associate  with an instance once registered. This is required when creating a profile for non-OCI instances.
        /// </summary>
        [Input("managementStationId")]
        public Input<string>? ManagementStationId { get; set; }

        /// <summary>
        /// The operating system family.
        /// </summary>
        [Input("osFamily")]
        public Input<string>? OsFamily { get; set; }

        /// <summary>
        /// The type of profile.
        /// </summary>
        [Input("profileType", required: true)]
        public Input<string> ProfileType { get; set; } = null!;

        /// <summary>
        /// The type of instance to register.
        /// </summary>
        [Input("registrationType")]
        public Input<string>? RegistrationType { get; set; }

        [Input("softwareSourceIds")]
        private InputList<string>? _softwareSourceIds;

        /// <summary>
        /// The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the registration profile will use.
        /// </summary>
        public InputList<string> SoftwareSourceIds
        {
            get => _softwareSourceIds ?? (_softwareSourceIds = new InputList<string>());
            set => _softwareSourceIds = value;
        }

        /// <summary>
        /// The vendor of the operating system for the instance.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("vendorName")]
        public Input<string>? VendorName { get; set; }

        public ProfileArgs()
        {
        }
        public static new ProfileArgs Empty => new ProfileArgs();
    }

    public sealed class ProfileState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The architecture type.
        /// </summary>
        [Input("archType")]
        public Input<string>? ArchType { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the registration profile.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) User-specified description of the registration profile.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique and you can change the name later. Avoid entering  confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.
        /// </summary>
        [Input("isDefaultProfile")]
        public Input<bool>? IsDefaultProfile { get; set; }

        /// <summary>
        /// Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.
        /// </summary>
        [Input("isServiceProvidedProfile")]
        public Input<bool>? IsServiceProvidedProfile { get; set; }

        [Input("lifecycleEnvironments")]
        private InputList<Inputs.ProfileLifecycleEnvironmentGetArgs>? _lifecycleEnvironments;

        /// <summary>
        /// Provides identifying information for the specified lifecycle environment.
        /// </summary>
        public InputList<Inputs.ProfileLifecycleEnvironmentGetArgs> LifecycleEnvironments
        {
            get => _lifecycleEnvironments ?? (_lifecycleEnvironments = new InputList<Inputs.ProfileLifecycleEnvironmentGetArgs>());
            set => _lifecycleEnvironments = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage that the instance will be associated with.
        /// </summary>
        [Input("lifecycleStageId")]
        public Input<string>? LifecycleStageId { get; set; }

        [Input("lifecycleStages")]
        private InputList<Inputs.ProfileLifecycleStageGetArgs>? _lifecycleStages;

        /// <summary>
        /// Provides identifying information for the specified lifecycle stage.
        /// </summary>
        public InputList<Inputs.ProfileLifecycleStageGetArgs> LifecycleStages
        {
            get => _lifecycleStages ?? (_lifecycleStages = new InputList<Inputs.ProfileLifecycleStageGetArgs>());
            set => _lifecycleStages = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group that the instance will join after registration.
        /// </summary>
        [Input("managedInstanceGroupId")]
        public Input<string>? ManagedInstanceGroupId { get; set; }

        [Input("managedInstanceGroups")]
        private InputList<Inputs.ProfileManagedInstanceGroupGetArgs>? _managedInstanceGroups;

        /// <summary>
        /// Provides identifying information for the specified managed instance group.
        /// </summary>
        public InputList<Inputs.ProfileManagedInstanceGroupGetArgs> ManagedInstanceGroups
        {
            get => _managedInstanceGroups ?? (_managedInstanceGroups = new InputList<Inputs.ProfileManagedInstanceGroupGetArgs>());
            set => _managedInstanceGroups = value;
        }

        /// <summary>
        /// description: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station to associate  with an instance once registered. This is required when creating a profile for non-OCI instances.
        /// </summary>
        [Input("managementStationId")]
        public Input<string>? ManagementStationId { get; set; }

        /// <summary>
        /// The operating system family.
        /// </summary>
        [Input("osFamily")]
        public Input<string>? OsFamily { get; set; }

        /// <summary>
        /// The type of profile.
        /// </summary>
        [Input("profileType")]
        public Input<string>? ProfileType { get; set; }

        /// <summary>
        /// The version of the profile. The version is automatically incremented each time the profiled is edited.
        /// </summary>
        [Input("profileVersion")]
        public Input<string>? ProfileVersion { get; set; }

        /// <summary>
        /// The type of instance to register.
        /// </summary>
        [Input("registrationType")]
        public Input<string>? RegistrationType { get; set; }

        [Input("softwareSourceIds")]
        private InputList<string>? _softwareSourceIds;

        /// <summary>
        /// The list of software source [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that the registration profile will use.
        /// </summary>
        public InputList<string> SoftwareSourceIds
        {
            get => _softwareSourceIds ?? (_softwareSourceIds = new InputList<string>());
            set => _softwareSourceIds = value;
        }

        [Input("softwareSources")]
        private InputList<Inputs.ProfileSoftwareSourceGetArgs>? _softwareSources;

        /// <summary>
        /// The list of software sources that the registration profile will use.
        /// </summary>
        public InputList<Inputs.ProfileSoftwareSourceGetArgs> SoftwareSources
        {
            get => _softwareSources ?? (_softwareSources = new InputList<Inputs.ProfileSoftwareSourceGetArgs>());
            set => _softwareSources = value;
        }

        /// <summary>
        /// The current state of the registration profile.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time the registration profile was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the registration profile was last modified (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        [Input("timeModified")]
        public Input<string>? TimeModified { get; set; }

        /// <summary>
        /// The vendor of the operating system for the instance.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("vendorName")]
        public Input<string>? VendorName { get; set; }

        public ProfileState()
        {
        }
        public static new ProfileState Empty => new ProfileState();
    }
}
