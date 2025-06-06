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
    /// This resource provides the Managed Instance Group Manage Module Streams Management resource in Oracle Cloud Infrastructure Os Management Hub service.
    /// 
    /// Enables or disables module streams and installs or removes module stream profiles. Once complete, the state of the modules, streams, and profiles will match the state indicated in the operation. See [ManageModuleStreamsOnManagedInstanceGroupDetails](https://docs.cloud.oracle.com/iaas/api/#/en/osmh/latest/datatypes/ManageModuleStreamsOnManagedInstanceGroupDetails) for more information.
    /// You can preform this operation as a dry run. For a dry run, the service evaluates the operation against the current module, stream, and profile state on the managed instance, but does not commit the changes. Instead, the service returns work request log or error entries indicating the impact of the operation.
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
    ///     var testManagedInstanceGroupManageModuleStreamsManagement = new Oci.OsManagementHub.ManagedInstanceGroupManageModuleStreamsManagement("test_managed_instance_group_manage_module_streams_management", new()
    ///     {
    ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
    ///         Disables = new[]
    ///         {
    ///             new Oci.OsManagementHub.Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableArgs
    ///             {
    ///                 ModuleName = managedInstanceGroupManageModuleStreamsManagementDisableModuleName,
    ///                 StreamName = testStream.Name,
    ///                 SoftwareSourceId = testSoftwareSource.Id,
    ///             },
    ///         },
    ///         Enables = new[]
    ///         {
    ///             new Oci.OsManagementHub.Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableArgs
    ///             {
    ///                 ModuleName = managedInstanceGroupManageModuleStreamsManagementEnableModuleName,
    ///                 StreamName = testStream.Name,
    ///                 SoftwareSourceId = testSoftwareSource.Id,
    ///             },
    ///         },
    ///         Installs = new[]
    ///         {
    ///             new Oci.OsManagementHub.Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallArgs
    ///             {
    ///                 ModuleName = managedInstanceGroupManageModuleStreamsManagementInstallModuleName,
    ///                 ProfileName = testProfile.Name,
    ///                 StreamName = testStream.Name,
    ///                 SoftwareSourceId = testSoftwareSource.Id,
    ///             },
    ///         },
    ///         IsDryRun = managedInstanceGroupManageModuleStreamsManagementIsDryRun,
    ///         Removes = new[]
    ///         {
    ///             new Oci.OsManagementHub.Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveArgs
    ///             {
    ///                 ModuleName = managedInstanceGroupManageModuleStreamsManagementRemoveModuleName,
    ///                 ProfileName = testProfile.Name,
    ///                 StreamName = testStream.Name,
    ///                 SoftwareSourceId = testSoftwareSource.Id,
    ///             },
    ///         },
    ///         WorkRequestDetails = new Oci.OsManagementHub.Inputs.ManagedInstanceGroupManageModuleStreamsManagementWorkRequestDetailsArgs
    ///         {
    ///             Description = managedInstanceGroupManageModuleStreamsManagementWorkRequestDetailsDescription,
    ///             DisplayName = managedInstanceGroupManageModuleStreamsManagementWorkRequestDetailsDisplayName,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ManagedInstanceGroupManageModuleStreamsManagement can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagementHub/managedInstanceGroupManageModuleStreamsManagement:ManagedInstanceGroupManageModuleStreamsManagement test_managed_instance_group_manage_module_streams_management "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagementHub/managedInstanceGroupManageModuleStreamsManagement:ManagedInstanceGroupManageModuleStreamsManagement")]
    public partial class ManagedInstanceGroupManageModuleStreamsManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The set of module streams to disable.
        /// </summary>
        [Output("disables")]
        public Output<ImmutableArray<Outputs.ManagedInstanceGroupManageModuleStreamsManagementDisable>> Disables { get; private set; } = null!;

        /// <summary>
        /// The set of module streams to enable.
        /// </summary>
        [Output("enables")]
        public Output<ImmutableArray<Outputs.ManagedInstanceGroupManageModuleStreamsManagementEnable>> Enables { get; private set; } = null!;

        /// <summary>
        /// The set of module stream profiles to install.
        /// </summary>
        [Output("installs")]
        public Output<ImmutableArray<Outputs.ManagedInstanceGroupManageModuleStreamsManagementInstall>> Installs { get; private set; } = null!;

        /// <summary>
        /// Indicates if this operation is a dry run or if the operation should be committed.  If set to true, the result of the operation will be evaluated but not committed.  If set to false, the operation is committed to the managed instance(s).  The default is false.
        /// </summary>
        [Output("isDryRun")]
        public Output<bool> IsDryRun { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Output("managedInstanceGroupId")]
        public Output<string> ManagedInstanceGroupId { get; private set; } = null!;

        /// <summary>
        /// The set of module stream profiles to remove.
        /// </summary>
        [Output("removes")]
        public Output<ImmutableArray<Outputs.ManagedInstanceGroupManageModuleStreamsManagementRemove>> Removes { get; private set; } = null!;

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Output("workRequestDetails")]
        public Output<Outputs.ManagedInstanceGroupManageModuleStreamsManagementWorkRequestDetails> WorkRequestDetails { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedInstanceGroupManageModuleStreamsManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedInstanceGroupManageModuleStreamsManagement(string name, ManagedInstanceGroupManageModuleStreamsManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/managedInstanceGroupManageModuleStreamsManagement:ManagedInstanceGroupManageModuleStreamsManagement", name, args ?? new ManagedInstanceGroupManageModuleStreamsManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedInstanceGroupManageModuleStreamsManagement(string name, Input<string> id, ManagedInstanceGroupManageModuleStreamsManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/managedInstanceGroupManageModuleStreamsManagement:ManagedInstanceGroupManageModuleStreamsManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedInstanceGroupManageModuleStreamsManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedInstanceGroupManageModuleStreamsManagement Get(string name, Input<string> id, ManagedInstanceGroupManageModuleStreamsManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedInstanceGroupManageModuleStreamsManagement(name, id, state, options);
        }
    }

    public sealed class ManagedInstanceGroupManageModuleStreamsManagementArgs : global::Pulumi.ResourceArgs
    {
        [Input("disables")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableArgs>? _disables;

        /// <summary>
        /// The set of module streams to disable.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableArgs> Disables
        {
            get => _disables ?? (_disables = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableArgs>());
            set => _disables = value;
        }

        [Input("enables")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableArgs>? _enables;

        /// <summary>
        /// The set of module streams to enable.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableArgs> Enables
        {
            get => _enables ?? (_enables = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableArgs>());
            set => _enables = value;
        }

        [Input("installs")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallArgs>? _installs;

        /// <summary>
        /// The set of module stream profiles to install.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallArgs> Installs
        {
            get => _installs ?? (_installs = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallArgs>());
            set => _installs = value;
        }

        /// <summary>
        /// Indicates if this operation is a dry run or if the operation should be committed.  If set to true, the result of the operation will be evaluated but not committed.  If set to false, the operation is committed to the managed instance(s).  The default is false.
        /// </summary>
        [Input("isDryRun")]
        public Input<bool>? IsDryRun { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId", required: true)]
        public Input<string> ManagedInstanceGroupId { get; set; } = null!;

        [Input("removes")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveArgs>? _removes;

        /// <summary>
        /// The set of module stream profiles to remove.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveArgs> Removes
        {
            get => _removes ?? (_removes = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveArgs>());
            set => _removes = value;
        }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.ManagedInstanceGroupManageModuleStreamsManagementWorkRequestDetailsArgs>? WorkRequestDetails { get; set; }

        public ManagedInstanceGroupManageModuleStreamsManagementArgs()
        {
        }
        public static new ManagedInstanceGroupManageModuleStreamsManagementArgs Empty => new ManagedInstanceGroupManageModuleStreamsManagementArgs();
    }

    public sealed class ManagedInstanceGroupManageModuleStreamsManagementState : global::Pulumi.ResourceArgs
    {
        [Input("disables")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableGetArgs>? _disables;

        /// <summary>
        /// The set of module streams to disable.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableGetArgs> Disables
        {
            get => _disables ?? (_disables = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementDisableGetArgs>());
            set => _disables = value;
        }

        [Input("enables")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableGetArgs>? _enables;

        /// <summary>
        /// The set of module streams to enable.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableGetArgs> Enables
        {
            get => _enables ?? (_enables = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementEnableGetArgs>());
            set => _enables = value;
        }

        [Input("installs")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallGetArgs>? _installs;

        /// <summary>
        /// The set of module stream profiles to install.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallGetArgs> Installs
        {
            get => _installs ?? (_installs = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementInstallGetArgs>());
            set => _installs = value;
        }

        /// <summary>
        /// Indicates if this operation is a dry run or if the operation should be committed.  If set to true, the result of the operation will be evaluated but not committed.  If set to false, the operation is committed to the managed instance(s).  The default is false.
        /// </summary>
        [Input("isDryRun")]
        public Input<bool>? IsDryRun { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId")]
        public Input<string>? ManagedInstanceGroupId { get; set; }

        [Input("removes")]
        private InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveGetArgs>? _removes;

        /// <summary>
        /// The set of module stream profiles to remove.
        /// </summary>
        public InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveGetArgs> Removes
        {
            get => _removes ?? (_removes = new InputList<Inputs.ManagedInstanceGroupManageModuleStreamsManagementRemoveGetArgs>());
            set => _removes = value;
        }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.ManagedInstanceGroupManageModuleStreamsManagementWorkRequestDetailsGetArgs>? WorkRequestDetails { get; set; }

        public ManagedInstanceGroupManageModuleStreamsManagementState()
        {
        }
        public static new ManagedInstanceGroupManageModuleStreamsManagementState Empty => new ManagedInstanceGroupManageModuleStreamsManagementState();
    }
}
