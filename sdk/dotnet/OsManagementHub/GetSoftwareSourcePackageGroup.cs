// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetSoftwareSourcePackageGroup
    {
        /// <summary>
        /// This data source provides details about a specific Software Source Package Group resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified package group from a software source.
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
        ///     var testSoftwareSourcePackageGroup = Oci.OsManagementHub.GetSoftwareSourcePackageGroup.Invoke(new()
        ///     {
        ///         PackageGroupId = testGroup.Id,
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSoftwareSourcePackageGroupResult> InvokeAsync(GetSoftwareSourcePackageGroupArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSoftwareSourcePackageGroupResult>("oci:OsManagementHub/getSoftwareSourcePackageGroup:getSoftwareSourcePackageGroup", args ?? new GetSoftwareSourcePackageGroupArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Software Source Package Group resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified package group from a software source.
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
        ///     var testSoftwareSourcePackageGroup = Oci.OsManagementHub.GetSoftwareSourcePackageGroup.Invoke(new()
        ///     {
        ///         PackageGroupId = testGroup.Id,
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourcePackageGroupResult> Invoke(GetSoftwareSourcePackageGroupInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourcePackageGroupResult>("oci:OsManagementHub/getSoftwareSourcePackageGroup:getSoftwareSourcePackageGroup", args ?? new GetSoftwareSourcePackageGroupInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Software Source Package Group resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns information about the specified package group from a software source.
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
        ///     var testSoftwareSourcePackageGroup = Oci.OsManagementHub.GetSoftwareSourcePackageGroup.Invoke(new()
        ///     {
        ///         PackageGroupId = testGroup.Id,
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourcePackageGroupResult> Invoke(GetSoftwareSourcePackageGroupInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourcePackageGroupResult>("oci:OsManagementHub/getSoftwareSourcePackageGroup:getSoftwareSourcePackageGroup", args ?? new GetSoftwareSourcePackageGroupInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSoftwareSourcePackageGroupArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique package group identifier.
        /// </summary>
        [Input("packageGroupId", required: true)]
        public string PackageGroupId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        [Input("softwareSourceId", required: true)]
        public string SoftwareSourceId { get; set; } = null!;

        public GetSoftwareSourcePackageGroupArgs()
        {
        }
        public static new GetSoftwareSourcePackageGroupArgs Empty => new GetSoftwareSourcePackageGroupArgs();
    }

    public sealed class GetSoftwareSourcePackageGroupInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique package group identifier.
        /// </summary>
        [Input("packageGroupId", required: true)]
        public Input<string> PackageGroupId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        [Input("softwareSourceId", required: true)]
        public Input<string> SoftwareSourceId { get; set; } = null!;

        public GetSoftwareSourcePackageGroupInvokeArgs()
        {
        }
        public static new GetSoftwareSourcePackageGroupInvokeArgs Empty => new GetSoftwareSourcePackageGroupInvokeArgs();
    }


    [OutputType]
    public sealed class GetSoftwareSourcePackageGroupResult
    {
        /// <summary>
        /// Description of the package group.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Indicates the order to display category or environment.
        /// </summary>
        public readonly int DisplayOrder;
        /// <summary>
        /// Indicates if this is a group, category, or environment.
        /// </summary>
        public readonly string GroupType;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates if this package group is the default.
        /// </summary>
        public readonly bool IsDefault;
        /// <summary>
        /// Indicates if this package group is visible to users.
        /// </summary>
        public readonly bool IsUserVisible;
        /// <summary>
        /// Package group name.
        /// </summary>
        public readonly string Name;
        public readonly string PackageGroupId;
        /// <summary>
        /// The list of packages in the package group.
        /// </summary>
        public readonly ImmutableArray<string> Packages;
        /// <summary>
        /// The repository IDs of the package group's repositories.
        /// </summary>
        public readonly ImmutableArray<string> Repositories;
        public readonly string SoftwareSourceId;

        [OutputConstructor]
        private GetSoftwareSourcePackageGroupResult(
            string description,

            int displayOrder,

            string groupType,

            string id,

            bool isDefault,

            bool isUserVisible,

            string name,

            string packageGroupId,

            ImmutableArray<string> packages,

            ImmutableArray<string> repositories,

            string softwareSourceId)
        {
            Description = description;
            DisplayOrder = displayOrder;
            GroupType = groupType;
            Id = id;
            IsDefault = isDefault;
            IsUserVisible = isUserVisible;
            Name = name;
            PackageGroupId = packageGroupId;
            Packages = packages;
            Repositories = repositories;
            SoftwareSourceId = softwareSourceId;
        }
    }
}
