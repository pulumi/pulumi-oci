// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp
{
    public static class GetSupportedVmwareSoftwareVersions
    {
        /// <summary>
        /// This data source provides the list of Supported Vmware Software Versions in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Lists the versions of bundled VMware software supported by the Oracle Cloud
        /// VMware Solution.
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
        ///     var testSupportedVmwareSoftwareVersions = Oci.Ocvp.GetSupportedVmwareSoftwareVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         HostShapeName = testShape.Name,
        ///         Version = supportedVmwareSoftwareVersionVersion,
        ///         VersionToUpgrade = supportedVmwareSoftwareVersionVersionToUpgrade,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSupportedVmwareSoftwareVersionsResult> InvokeAsync(GetSupportedVmwareSoftwareVersionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSupportedVmwareSoftwareVersionsResult>("oci:Ocvp/getSupportedVmwareSoftwareVersions:getSupportedVmwareSoftwareVersions", args ?? new GetSupportedVmwareSoftwareVersionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Supported Vmware Software Versions in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Lists the versions of bundled VMware software supported by the Oracle Cloud
        /// VMware Solution.
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
        ///     var testSupportedVmwareSoftwareVersions = Oci.Ocvp.GetSupportedVmwareSoftwareVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         HostShapeName = testShape.Name,
        ///         Version = supportedVmwareSoftwareVersionVersion,
        ///         VersionToUpgrade = supportedVmwareSoftwareVersionVersionToUpgrade,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSupportedVmwareSoftwareVersionsResult> Invoke(GetSupportedVmwareSoftwareVersionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSupportedVmwareSoftwareVersionsResult>("oci:Ocvp/getSupportedVmwareSoftwareVersions:getSupportedVmwareSoftwareVersions", args ?? new GetSupportedVmwareSoftwareVersionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Supported Vmware Software Versions in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Lists the versions of bundled VMware software supported by the Oracle Cloud
        /// VMware Solution.
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
        ///     var testSupportedVmwareSoftwareVersions = Oci.Ocvp.GetSupportedVmwareSoftwareVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         HostShapeName = testShape.Name,
        ///         Version = supportedVmwareSoftwareVersionVersion,
        ///         VersionToUpgrade = supportedVmwareSoftwareVersionVersionToUpgrade,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSupportedVmwareSoftwareVersionsResult> Invoke(GetSupportedVmwareSoftwareVersionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSupportedVmwareSoftwareVersionsResult>("oci:Ocvp/getSupportedVmwareSoftwareVersions:getSupportedVmwareSoftwareVersions", args ?? new GetSupportedVmwareSoftwareVersionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSupportedVmwareSoftwareVersionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetSupportedVmwareSoftwareVersionsFilterArgs>? _filters;
        public List<Inputs.GetSupportedVmwareSoftwareVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSupportedVmwareSoftwareVersionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match or support the given ESXi host shape.
        /// </summary>
        [Input("hostShapeName")]
        public string? HostShapeName { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given VMware software version exactly.
        /// </summary>
        [Input("version")]
        public string? Version { get; set; }

        /// <summary>
        /// A filter to return only VMware software versions that the given VMware software version can be upgraded to.
        /// </summary>
        [Input("versionToUpgrade")]
        public string? VersionToUpgrade { get; set; }

        public GetSupportedVmwareSoftwareVersionsArgs()
        {
        }
        public static new GetSupportedVmwareSoftwareVersionsArgs Empty => new GetSupportedVmwareSoftwareVersionsArgs();
    }

    public sealed class GetSupportedVmwareSoftwareVersionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetSupportedVmwareSoftwareVersionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetSupportedVmwareSoftwareVersionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSupportedVmwareSoftwareVersionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match or support the given ESXi host shape.
        /// </summary>
        [Input("hostShapeName")]
        public Input<string>? HostShapeName { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given VMware software version exactly.
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        /// <summary>
        /// A filter to return only VMware software versions that the given VMware software version can be upgraded to.
        /// </summary>
        [Input("versionToUpgrade")]
        public Input<string>? VersionToUpgrade { get; set; }

        public GetSupportedVmwareSoftwareVersionsInvokeArgs()
        {
        }
        public static new GetSupportedVmwareSoftwareVersionsInvokeArgs Empty => new GetSupportedVmwareSoftwareVersionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetSupportedVmwareSoftwareVersionsResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsFilterResult> Filters;
        public readonly string? HostShapeName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of the supported versions of bundled VMware software.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsItemResult> Items;
        /// <summary>
        /// A short, unique string that identifies the version of bundled software.
        /// </summary>
        public readonly string? Version;
        public readonly string? VersionToUpgrade;

        [OutputConstructor]
        private GetSupportedVmwareSoftwareVersionsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsFilterResult> filters,

            string? hostShapeName,

            string id,

            ImmutableArray<Outputs.GetSupportedVmwareSoftwareVersionsItemResult> items,

            string? version,

            string? versionToUpgrade)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            HostShapeName = hostShapeName;
            Id = id;
            Items = items;
            Version = version;
            VersionToUpgrade = versionToUpgrade;
        }
    }
}
