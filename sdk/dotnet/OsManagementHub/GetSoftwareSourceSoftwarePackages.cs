// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetSoftwareSourceSoftwarePackages
    {
        /// <summary>
        /// This data source provides the list of Software Source Software Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists software packages in the specified software source.  Filter the list against a variety of criteria 
        /// including but not limited to its name.
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
        ///     var testSoftwareSourceSoftwarePackages = Oci.OsManagementHub.GetSoftwareSourceSoftwarePackages.Invoke(new()
        ///     {
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///         DisplayName = softwareSourceSoftwarePackageDisplayName,
        ///         DisplayNameContains = softwareSourceSoftwarePackageDisplayNameContains,
        ///         IsLatest = softwareSourceSoftwarePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSoftwareSourceSoftwarePackagesResult> InvokeAsync(GetSoftwareSourceSoftwarePackagesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSoftwareSourceSoftwarePackagesResult>("oci:OsManagementHub/getSoftwareSourceSoftwarePackages:getSoftwareSourceSoftwarePackages", args ?? new GetSoftwareSourceSoftwarePackagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Software Source Software Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists software packages in the specified software source.  Filter the list against a variety of criteria 
        /// including but not limited to its name.
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
        ///     var testSoftwareSourceSoftwarePackages = Oci.OsManagementHub.GetSoftwareSourceSoftwarePackages.Invoke(new()
        ///     {
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///         DisplayName = softwareSourceSoftwarePackageDisplayName,
        ///         DisplayNameContains = softwareSourceSoftwarePackageDisplayNameContains,
        ///         IsLatest = softwareSourceSoftwarePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourceSoftwarePackagesResult> Invoke(GetSoftwareSourceSoftwarePackagesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourceSoftwarePackagesResult>("oci:OsManagementHub/getSoftwareSourceSoftwarePackages:getSoftwareSourceSoftwarePackages", args ?? new GetSoftwareSourceSoftwarePackagesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Software Source Software Packages in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Lists software packages in the specified software source.  Filter the list against a variety of criteria 
        /// including but not limited to its name.
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
        ///     var testSoftwareSourceSoftwarePackages = Oci.OsManagementHub.GetSoftwareSourceSoftwarePackages.Invoke(new()
        ///     {
        ///         SoftwareSourceId = testSoftwareSource.Id,
        ///         DisplayName = softwareSourceSoftwarePackageDisplayName,
        ///         DisplayNameContains = softwareSourceSoftwarePackageDisplayNameContains,
        ///         IsLatest = softwareSourceSoftwarePackageIsLatest,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSoftwareSourceSoftwarePackagesResult> Invoke(GetSoftwareSourceSoftwarePackagesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSoftwareSourceSoftwarePackagesResult>("oci:OsManagementHub/getSoftwareSourceSoftwarePackages:getSoftwareSourceSoftwarePackages", args ?? new GetSoftwareSourceSoftwarePackagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSoftwareSourceSoftwarePackagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return resources that match the given user-friendly name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// A filter to return resources that may partially match the given display name.
        /// </summary>
        [Input("displayNameContains")]
        public string? DisplayNameContains { get; set; }

        [Input("filters")]
        private List<Inputs.GetSoftwareSourceSoftwarePackagesFilterArgs>? _filters;
        public List<Inputs.GetSoftwareSourceSoftwarePackagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSoftwareSourceSoftwarePackagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
        /// </summary>
        [Input("isLatest")]
        public bool? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        [Input("softwareSourceId", required: true)]
        public string SoftwareSourceId { get; set; } = null!;

        public GetSoftwareSourceSoftwarePackagesArgs()
        {
        }
        public static new GetSoftwareSourceSoftwarePackagesArgs Empty => new GetSoftwareSourceSoftwarePackagesArgs();
    }

    public sealed class GetSoftwareSourceSoftwarePackagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return resources that match the given user-friendly name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A filter to return resources that may partially match the given display name.
        /// </summary>
        [Input("displayNameContains")]
        public Input<string>? DisplayNameContains { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetSoftwareSourceSoftwarePackagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSoftwareSourceSoftwarePackagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSoftwareSourceSoftwarePackagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Indicates whether to list only the latest versions of packages, module streams, and stream profiles.
        /// </summary>
        [Input("isLatest")]
        public Input<bool>? IsLatest { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        [Input("softwareSourceId", required: true)]
        public Input<string> SoftwareSourceId { get; set; } = null!;

        public GetSoftwareSourceSoftwarePackagesInvokeArgs()
        {
        }
        public static new GetSoftwareSourceSoftwarePackagesInvokeArgs Empty => new GetSoftwareSourceSoftwarePackagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSoftwareSourceSoftwarePackagesResult
    {
        /// <summary>
        /// Software source name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string? DisplayNameContains;
        public readonly ImmutableArray<Outputs.GetSoftwareSourceSoftwarePackagesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether this package is the latest version.
        /// </summary>
        public readonly bool? IsLatest;
        /// <summary>
        /// The list of software_package_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionResult> SoftwarePackageCollections;
        public readonly string SoftwareSourceId;

        [OutputConstructor]
        private GetSoftwareSourceSoftwarePackagesResult(
            string? displayName,

            string? displayNameContains,

            ImmutableArray<Outputs.GetSoftwareSourceSoftwarePackagesFilterResult> filters,

            string id,

            bool? isLatest,

            ImmutableArray<Outputs.GetSoftwareSourceSoftwarePackagesSoftwarePackageCollectionResult> softwarePackageCollections,

            string softwareSourceId)
        {
            DisplayName = displayName;
            DisplayNameContains = displayNameContains;
            Filters = filters;
            Id = id;
            IsLatest = isLatest;
            SoftwarePackageCollections = softwarePackageCollections;
            SoftwareSourceId = softwareSourceId;
        }
    }
}
