// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetManagedInstanceGroupAvailablePackages
    {
        /// <summary>
        /// This data source provides the list of Managed Instance Group Available Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists available packages on the specified managed instances group. Filter the list against a variety 
        /// of criteria including but not limited to the package name.
        /// 
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
        ///     var testManagedInstanceGroupAvailablePackages = Oci.OsManagementHub.GetManagedInstanceGroupAvailablePackages.Invoke(new()
        ///     {
        ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayNames = managedInstanceGroupAvailablePackageDisplayName,
        ///         DisplayNameContains = managedInstanceGroupAvailablePackageDisplayNameContains,
        ///         IsLatest = managedInstanceGroupAvailablePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedInstanceGroupAvailablePackagesResult> InvokeAsync(GetManagedInstanceGroupAvailablePackagesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedInstanceGroupAvailablePackagesResult>("oci:OsManagementHub/getManagedInstanceGroupAvailablePackages:getManagedInstanceGroupAvailablePackages", args ?? new GetManagedInstanceGroupAvailablePackagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Group Available Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists available packages on the specified managed instances group. Filter the list against a variety 
        /// of criteria including but not limited to the package name.
        /// 
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
        ///     var testManagedInstanceGroupAvailablePackages = Oci.OsManagementHub.GetManagedInstanceGroupAvailablePackages.Invoke(new()
        ///     {
        ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayNames = managedInstanceGroupAvailablePackageDisplayName,
        ///         DisplayNameContains = managedInstanceGroupAvailablePackageDisplayNameContains,
        ///         IsLatest = managedInstanceGroupAvailablePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedInstanceGroupAvailablePackagesResult> Invoke(GetManagedInstanceGroupAvailablePackagesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedInstanceGroupAvailablePackagesResult>("oci:OsManagementHub/getManagedInstanceGroupAvailablePackages:getManagedInstanceGroupAvailablePackages", args ?? new GetManagedInstanceGroupAvailablePackagesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Instance Group Available Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists available packages on the specified managed instances group. Filter the list against a variety 
        /// of criteria including but not limited to the package name.
        /// 
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
        ///     var testManagedInstanceGroupAvailablePackages = Oci.OsManagementHub.GetManagedInstanceGroupAvailablePackages.Invoke(new()
        ///     {
        ///         ManagedInstanceGroupId = testManagedInstanceGroup.Id,
        ///         CompartmentId = compartmentId,
        ///         DisplayNames = managedInstanceGroupAvailablePackageDisplayName,
        ///         DisplayNameContains = managedInstanceGroupAvailablePackageDisplayNameContains,
        ///         IsLatest = managedInstanceGroupAvailablePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedInstanceGroupAvailablePackagesResult> Invoke(GetManagedInstanceGroupAvailablePackagesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedInstanceGroupAvailablePackagesResult>("oci:OsManagementHub/getManagedInstanceGroupAvailablePackages:getManagedInstanceGroupAvailablePackages", args ?? new GetManagedInstanceGroupAvailablePackagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedInstanceGroupAvailablePackagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return resources that may partially match the given display name.
        /// </summary>
        [Input("displayNameContains")]
        public string? DisplayNameContains { get; set; }

        [Input("displayNames")]
        private List<string>? _displayNames;

        /// <summary>
        /// A filter to return resources that match the given display names.
        /// </summary>
        public List<string> DisplayNames
        {
            get => _displayNames ?? (_displayNames = new List<string>());
            set => _displayNames = value;
        }

        [Input("filters")]
        private List<Inputs.GetManagedInstanceGroupAvailablePackagesFilterArgs>? _filters;
        public List<Inputs.GetManagedInstanceGroupAvailablePackagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedInstanceGroupAvailablePackagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
        /// </summary>
        [Input("isLatest")]
        public bool? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId", required: true)]
        public string ManagedInstanceGroupId { get; set; } = null!;

        public GetManagedInstanceGroupAvailablePackagesArgs()
        {
        }
        public static new GetManagedInstanceGroupAvailablePackagesArgs Empty => new GetManagedInstanceGroupAvailablePackagesArgs();
    }

    public sealed class GetManagedInstanceGroupAvailablePackagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return resources that may partially match the given display name.
        /// </summary>
        [Input("displayNameContains")]
        public Input<string>? DisplayNameContains { get; set; }

        [Input("displayNames")]
        private InputList<string>? _displayNames;

        /// <summary>
        /// A filter to return resources that match the given display names.
        /// </summary>
        public InputList<string> DisplayNames
        {
            get => _displayNames ?? (_displayNames = new InputList<string>());
            set => _displayNames = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetManagedInstanceGroupAvailablePackagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedInstanceGroupAvailablePackagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedInstanceGroupAvailablePackagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
        /// </summary>
        [Input("isLatest")]
        public Input<bool>? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
        /// </summary>
        [Input("managedInstanceGroupId", required: true)]
        public Input<string> ManagedInstanceGroupId { get; set; } = null!;

        public GetManagedInstanceGroupAvailablePackagesInvokeArgs()
        {
        }
        public static new GetManagedInstanceGroupAvailablePackagesInvokeArgs Empty => new GetManagedInstanceGroupAvailablePackagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedInstanceGroupAvailablePackagesResult
    {
        public readonly string? CompartmentId;
        public readonly string? DisplayNameContains;
        /// <summary>
        /// Software source name.
        /// </summary>
        public readonly ImmutableArray<string> DisplayNames;
        public readonly ImmutableArray<Outputs.GetManagedInstanceGroupAvailablePackagesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether this is the latest package version.
        /// </summary>
        public readonly bool? IsLatest;
        /// <summary>
        /// The list of managed_instance_group_available_package_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollectionResult> ManagedInstanceGroupAvailablePackageCollections;
        public readonly string ManagedInstanceGroupId;

        [OutputConstructor]
        private GetManagedInstanceGroupAvailablePackagesResult(
            string? compartmentId,

            string? displayNameContains,

            ImmutableArray<string> displayNames,

            ImmutableArray<Outputs.GetManagedInstanceGroupAvailablePackagesFilterResult> filters,

            string id,

            bool? isLatest,

            ImmutableArray<Outputs.GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollectionResult> managedInstanceGroupAvailablePackageCollections,

            string managedInstanceGroupId)
        {
            CompartmentId = compartmentId;
            DisplayNameContains = displayNameContains;
            DisplayNames = displayNames;
            Filters = filters;
            Id = id;
            IsLatest = isLatest;
            ManagedInstanceGroupAvailablePackageCollections = managedInstanceGroupAvailablePackageCollections;
            ManagedInstanceGroupId = managedInstanceGroupId;
        }
    }
}
