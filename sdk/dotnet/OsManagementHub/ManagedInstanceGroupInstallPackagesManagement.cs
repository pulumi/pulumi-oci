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
    /// This resource provides the Managed Instance Group Install Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.
    /// 
    /// Installs the specified packages on each managed instance in a managed instance group. The package must be compatible with the instances in the group.
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
    ///     var testManagedInstanceGroupInstallPackagesManagement = new Oci.OsManagementHub.ManagedInstanceGroupInstallPackagesManagement("test_managed_instance_group_install_packages_management", new()
    ///     {
    ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
    ///         PackageNames = managedInstanceGroupInstallPackagesManagementPackageNames,
    ///         IsLatest = managedInstanceGroupInstallPackagesManagementIsLatest,
    ///         WorkRequestDetails = new Oci.OsManagementHub.Inputs.ManagedInstanceGroupInstallPackagesManagementWorkRequestDetailsArgs
    ///         {
    ///             Description = managedInstanceGroupInstallPackagesManagementWorkRequestDetailsDescription,
    ///             DisplayName = managedInstanceGroupInstallPackagesManagementWorkRequestDetailsDisplayName,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ManagedInstanceGroupInstallPackagesManagement can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:OsManagementHub/managedInstanceGroupInstallPackagesManagement:ManagedInstanceGroupInstallPackagesManagement test_managed_instance_group_install_packages_management "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:OsManagementHub/managedInstanceGroupInstallPackagesManagement:ManagedInstanceGroupInstallPackagesManagement")]
    public partial class ManagedInstanceGroupInstallPackagesManagement : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Indicates whether this is the latest package version.
        /// </summary>
        [Output("isLatest")]
        public Output<bool> IsLatest { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Output("managedInstanceGroupId")]
        public Output<string> ManagedInstanceGroupId { get; private set; } = null!;

        /// <summary>
        /// The list of package names.
        /// </summary>
        [Output("packageNames")]
        public Output<ImmutableArray<string>> PackageNames { get; private set; } = null!;

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Output("workRequestDetails")]
        public Output<Outputs.ManagedInstanceGroupInstallPackagesManagementWorkRequestDetails> WorkRequestDetails { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedInstanceGroupInstallPackagesManagement resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedInstanceGroupInstallPackagesManagement(string name, ManagedInstanceGroupInstallPackagesManagementArgs args, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/managedInstanceGroupInstallPackagesManagement:ManagedInstanceGroupInstallPackagesManagement", name, args ?? new ManagedInstanceGroupInstallPackagesManagementArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedInstanceGroupInstallPackagesManagement(string name, Input<string> id, ManagedInstanceGroupInstallPackagesManagementState? state = null, CustomResourceOptions? options = null)
            : base("oci:OsManagementHub/managedInstanceGroupInstallPackagesManagement:ManagedInstanceGroupInstallPackagesManagement", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedInstanceGroupInstallPackagesManagement resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedInstanceGroupInstallPackagesManagement Get(string name, Input<string> id, ManagedInstanceGroupInstallPackagesManagementState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedInstanceGroupInstallPackagesManagement(name, id, state, options);
        }
    }

    public sealed class ManagedInstanceGroupInstallPackagesManagementArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Indicates whether this is the latest package version.
        /// </summary>
        [Input("isLatest")]
        public Input<bool>? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId", required: true)]
        public Input<string> ManagedInstanceGroupId { get; set; } = null!;

        [Input("packageNames", required: true)]
        private InputList<string>? _packageNames;

        /// <summary>
        /// The list of package names.
        /// </summary>
        public InputList<string> PackageNames
        {
            get => _packageNames ?? (_packageNames = new InputList<string>());
            set => _packageNames = value;
        }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.ManagedInstanceGroupInstallPackagesManagementWorkRequestDetailsArgs>? WorkRequestDetails { get; set; }

        public ManagedInstanceGroupInstallPackagesManagementArgs()
        {
        }
        public static new ManagedInstanceGroupInstallPackagesManagementArgs Empty => new ManagedInstanceGroupInstallPackagesManagementArgs();
    }

    public sealed class ManagedInstanceGroupInstallPackagesManagementState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Indicates whether this is the latest package version.
        /// </summary>
        [Input("isLatest")]
        public Input<bool>? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId")]
        public Input<string>? ManagedInstanceGroupId { get; set; }

        [Input("packageNames")]
        private InputList<string>? _packageNames;

        /// <summary>
        /// The list of package names.
        /// </summary>
        public InputList<string> PackageNames
        {
            get => _packageNames ?? (_packageNames = new InputList<string>());
            set => _packageNames = value;
        }

        /// <summary>
        /// Provides the name and description of the job.
        /// </summary>
        [Input("workRequestDetails")]
        public Input<Inputs.ManagedInstanceGroupInstallPackagesManagementWorkRequestDetailsGetArgs>? WorkRequestDetails { get; set; }

        public ManagedInstanceGroupInstallPackagesManagementState()
        {
        }
        public static new ManagedInstanceGroupInstallPackagesManagementState Empty => new ManagedInstanceGroupInstallPackagesManagementState();
    }
}
