// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement
{
    /// <summary>
    /// This resource provides the Managed Instance resource in Oracle Cloud Infrastructure OS Management service.
    /// 
    /// Updates a specific Managed Instance.
    /// 
    /// ## Import
    /// 
    /// ManagedInstances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagement/managedInstance:ManagedInstance test_managed_instance "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagement/managedInstance:ManagedInstance")]
    public partial class ManagedInstance : global::Pulumi.CustomResource
    {
        /// <summary>
        /// if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
        /// </summary>
        [Output("autonomouses")]
        public Output<ImmutableArray<Outputs.ManagedInstanceAutonomouse>> Autonomouses { get; private set; } = null!;

        /// <summary>
        /// Number of bug fix type updates available to be installed
        /// </summary>
        [Output("bugUpdatesAvailable")]
        public Output<int> BugUpdatesAvailable { get; private set; } = null!;

        /// <summary>
        /// list of child Software Sources attached to the Managed Instance
        /// </summary>
        [Output("childSoftwareSources")]
        public Output<ImmutableArray<Outputs.ManagedInstanceChildSoftwareSource>> ChildSoftwareSources { get; private set; } = null!;

        /// <summary>
        /// OCID for the Compartment
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Information specified by the user about the managed instance
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// User friendly name
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Number of enhancement type updates available to be installed
        /// </summary>
        [Output("enhancementUpdatesAvailable")]
        public Output<int> EnhancementUpdatesAvailable { get; private set; } = null!;

        /// <summary>
        /// (Updatable) True if user allow data collection for this instance
        /// </summary>
        [Output("isDataCollectionAuthorized")]
        public Output<bool> IsDataCollectionAuthorized { get; private set; } = null!;

        /// <summary>
        /// Indicates whether a reboot is required to complete installation of updates.
        /// </summary>
        [Output("isRebootRequired")]
        public Output<bool> IsRebootRequired { get; private set; } = null!;

        /// <summary>
        /// The ksplice effective kernel version
        /// </summary>
        [Output("kspliceEffectiveKernelVersion")]
        public Output<string> KspliceEffectiveKernelVersion { get; private set; } = null!;

        /// <summary>
        /// Time at which the instance last booted
        /// </summary>
        [Output("lastBoot")]
        public Output<string> LastBoot { get; private set; } = null!;

        /// <summary>
        /// Time at which the instance last checked in
        /// </summary>
        [Output("lastCheckin")]
        public Output<string> LastCheckin { get; private set; } = null!;

        /// <summary>
        /// The ids of the managed instance groups of which this instance is a member.
        /// </summary>
        [Output("managedInstanceGroups")]
        public Output<ImmutableArray<Outputs.ManagedInstanceManagedInstanceGroup>> ManagedInstanceGroups { get; private set; } = null!;

        /// <summary>
        /// OCID for the managed instance
        /// </summary>
        [Output("managedInstanceId")]
        public Output<string> ManagedInstanceId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OCID of the ONS topic used to send notification to users
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("notificationTopicId")]
        public Output<string> NotificationTopicId { get; private set; } = null!;

        /// <summary>
        /// The Operating System type of the managed instance.
        /// </summary>
        [Output("osFamily")]
        public Output<string> OsFamily { get; private set; } = null!;

        /// <summary>
        /// Operating System Kernel Version
        /// </summary>
        [Output("osKernelVersion")]
        public Output<string> OsKernelVersion { get; private set; } = null!;

        /// <summary>
        /// Operating System Name
        /// </summary>
        [Output("osName")]
        public Output<string> OsName { get; private set; } = null!;

        /// <summary>
        /// Operating System Version
        /// </summary>
        [Output("osVersion")]
        public Output<string> OsVersion { get; private set; } = null!;

        /// <summary>
        /// Number of non-classified updates available to be installed
        /// </summary>
        [Output("otherUpdatesAvailable")]
        public Output<int> OtherUpdatesAvailable { get; private set; } = null!;

        /// <summary>
        /// the parent (base) Software Source attached to the Managed Instance
        /// </summary>
        [Output("parentSoftwareSources")]
        public Output<ImmutableArray<Outputs.ManagedInstanceParentSoftwareSource>> ParentSoftwareSources { get; private set; } = null!;

        /// <summary>
        /// Number of scheduled jobs associated with this instance
        /// </summary>
        [Output("scheduledJobCount")]
        public Output<int> ScheduledJobCount { get; private set; } = null!;

        /// <summary>
        /// Number of security type updates available to be installed
        /// </summary>
        [Output("securityUpdatesAvailable")]
        public Output<int> SecurityUpdatesAvailable { get; private set; } = null!;

        /// <summary>
        /// status of the managed instance.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// Number of updates available to be installed
        /// </summary>
        [Output("updatesAvailable")]
        public Output<int> UpdatesAvailable { get; private set; } = null!;

        /// <summary>
        /// Number of work requests associated with this instance
        /// </summary>
        [Output("workRequestCount")]
        public Output<int> WorkRequestCount { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedInstance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedInstance(string name, ManagedInstanceArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagement/managedInstance:ManagedInstance", name, args ?? new ManagedInstanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedInstance(string name, Input<string> id, ManagedInstanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagement/managedInstance:ManagedInstance", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedInstance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedInstance Get(string name, Input<string> id, ManagedInstanceState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedInstance(name, id, state, options);
        }
    }

    public sealed class ManagedInstanceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) True if user allow data collection for this instance
        /// </summary>
        [Input("isDataCollectionAuthorized")]
        public Input<bool>? IsDataCollectionAuthorized { get; set; }

        /// <summary>
        /// OCID for the managed instance
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public Input<string> ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// (Updatable) OCID of the ONS topic used to send notification to users
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("notificationTopicId")]
        public Input<string>? NotificationTopicId { get; set; }

        public ManagedInstanceArgs()
        {
        }
        public static new ManagedInstanceArgs Empty => new ManagedInstanceArgs();
    }

    public sealed class ManagedInstanceState : global::Pulumi.ResourceArgs
    {
        [Input("autonomouses")]
        private InputList<Inputs.ManagedInstanceAutonomouseGetArgs>? _autonomouses;

        /// <summary>
        /// if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
        /// </summary>
        public InputList<Inputs.ManagedInstanceAutonomouseGetArgs> Autonomouses
        {
            get => _autonomouses ?? (_autonomouses = new InputList<Inputs.ManagedInstanceAutonomouseGetArgs>());
            set => _autonomouses = value;
        }

        /// <summary>
        /// Number of bug fix type updates available to be installed
        /// </summary>
        [Input("bugUpdatesAvailable")]
        public Input<int>? BugUpdatesAvailable { get; set; }

        [Input("childSoftwareSources")]
        private InputList<Inputs.ManagedInstanceChildSoftwareSourceGetArgs>? _childSoftwareSources;

        /// <summary>
        /// list of child Software Sources attached to the Managed Instance
        /// </summary>
        public InputList<Inputs.ManagedInstanceChildSoftwareSourceGetArgs> ChildSoftwareSources
        {
            get => _childSoftwareSources ?? (_childSoftwareSources = new InputList<Inputs.ManagedInstanceChildSoftwareSourceGetArgs>());
            set => _childSoftwareSources = value;
        }

        /// <summary>
        /// OCID for the Compartment
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Information specified by the user about the managed instance
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// User friendly name
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Number of enhancement type updates available to be installed
        /// </summary>
        [Input("enhancementUpdatesAvailable")]
        public Input<int>? EnhancementUpdatesAvailable { get; set; }

        /// <summary>
        /// (Updatable) True if user allow data collection for this instance
        /// </summary>
        [Input("isDataCollectionAuthorized")]
        public Input<bool>? IsDataCollectionAuthorized { get; set; }

        /// <summary>
        /// Indicates whether a reboot is required to complete installation of updates.
        /// </summary>
        [Input("isRebootRequired")]
        public Input<bool>? IsRebootRequired { get; set; }

        /// <summary>
        /// The ksplice effective kernel version
        /// </summary>
        [Input("kspliceEffectiveKernelVersion")]
        public Input<string>? KspliceEffectiveKernelVersion { get; set; }

        /// <summary>
        /// Time at which the instance last booted
        /// </summary>
        [Input("lastBoot")]
        public Input<string>? LastBoot { get; set; }

        /// <summary>
        /// Time at which the instance last checked in
        /// </summary>
        [Input("lastCheckin")]
        public Input<string>? LastCheckin { get; set; }

        [Input("managedInstanceGroups")]
        private InputList<Inputs.ManagedInstanceManagedInstanceGroupGetArgs>? _managedInstanceGroups;

        /// <summary>
        /// The ids of the managed instance groups of which this instance is a member.
        /// </summary>
        public InputList<Inputs.ManagedInstanceManagedInstanceGroupGetArgs> ManagedInstanceGroups
        {
            get => _managedInstanceGroups ?? (_managedInstanceGroups = new InputList<Inputs.ManagedInstanceManagedInstanceGroupGetArgs>());
            set => _managedInstanceGroups = value;
        }

        /// <summary>
        /// OCID for the managed instance
        /// </summary>
        [Input("managedInstanceId")]
        public Input<string>? ManagedInstanceId { get; set; }

        /// <summary>
        /// (Updatable) OCID of the ONS topic used to send notification to users
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("notificationTopicId")]
        public Input<string>? NotificationTopicId { get; set; }

        /// <summary>
        /// The Operating System type of the managed instance.
        /// </summary>
        [Input("osFamily")]
        public Input<string>? OsFamily { get; set; }

        /// <summary>
        /// Operating System Kernel Version
        /// </summary>
        [Input("osKernelVersion")]
        public Input<string>? OsKernelVersion { get; set; }

        /// <summary>
        /// Operating System Name
        /// </summary>
        [Input("osName")]
        public Input<string>? OsName { get; set; }

        /// <summary>
        /// Operating System Version
        /// </summary>
        [Input("osVersion")]
        public Input<string>? OsVersion { get; set; }

        /// <summary>
        /// Number of non-classified updates available to be installed
        /// </summary>
        [Input("otherUpdatesAvailable")]
        public Input<int>? OtherUpdatesAvailable { get; set; }

        [Input("parentSoftwareSources")]
        private InputList<Inputs.ManagedInstanceParentSoftwareSourceGetArgs>? _parentSoftwareSources;

        /// <summary>
        /// the parent (base) Software Source attached to the Managed Instance
        /// </summary>
        public InputList<Inputs.ManagedInstanceParentSoftwareSourceGetArgs> ParentSoftwareSources
        {
            get => _parentSoftwareSources ?? (_parentSoftwareSources = new InputList<Inputs.ManagedInstanceParentSoftwareSourceGetArgs>());
            set => _parentSoftwareSources = value;
        }

        /// <summary>
        /// Number of scheduled jobs associated with this instance
        /// </summary>
        [Input("scheduledJobCount")]
        public Input<int>? ScheduledJobCount { get; set; }

        /// <summary>
        /// Number of security type updates available to be installed
        /// </summary>
        [Input("securityUpdatesAvailable")]
        public Input<int>? SecurityUpdatesAvailable { get; set; }

        /// <summary>
        /// status of the managed instance.
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        /// <summary>
        /// Number of updates available to be installed
        /// </summary>
        [Input("updatesAvailable")]
        public Input<int>? UpdatesAvailable { get; set; }

        /// <summary>
        /// Number of work requests associated with this instance
        /// </summary>
        [Input("workRequestCount")]
        public Input<int>? WorkRequestCount { get; set; }

        public ManagedInstanceState()
        {
        }
        public static new ManagedInstanceState Empty => new ManagedInstanceState();
    }
}
