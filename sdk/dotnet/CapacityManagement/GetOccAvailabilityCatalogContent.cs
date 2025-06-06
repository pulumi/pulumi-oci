// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement
{
    public static class GetOccAvailabilityCatalogContent
    {
        /// <summary>
        /// This data source provides details about a specific Occ Availability Catalog Content resource in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Returns the binary contents of the availability catalog. Can be saved as a csv file.
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
        ///     var testOccAvailabilityCatalogContent = Oci.CapacityManagement.GetOccAvailabilityCatalogContent.Invoke(new()
        ///     {
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOccAvailabilityCatalogContentResult> InvokeAsync(GetOccAvailabilityCatalogContentArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOccAvailabilityCatalogContentResult>("oci:CapacityManagement/getOccAvailabilityCatalogContent:getOccAvailabilityCatalogContent", args ?? new GetOccAvailabilityCatalogContentArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Occ Availability Catalog Content resource in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Returns the binary contents of the availability catalog. Can be saved as a csv file.
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
        ///     var testOccAvailabilityCatalogContent = Oci.CapacityManagement.GetOccAvailabilityCatalogContent.Invoke(new()
        ///     {
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccAvailabilityCatalogContentResult> Invoke(GetOccAvailabilityCatalogContentInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccAvailabilityCatalogContentResult>("oci:CapacityManagement/getOccAvailabilityCatalogContent:getOccAvailabilityCatalogContent", args ?? new GetOccAvailabilityCatalogContentInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Occ Availability Catalog Content resource in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Returns the binary contents of the availability catalog. Can be saved as a csv file.
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
        ///     var testOccAvailabilityCatalogContent = Oci.CapacityManagement.GetOccAvailabilityCatalogContent.Invoke(new()
        ///     {
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccAvailabilityCatalogContentResult> Invoke(GetOccAvailabilityCatalogContentInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccAvailabilityCatalogContentResult>("oci:CapacityManagement/getOccAvailabilityCatalogContent:getOccAvailabilityCatalogContent", args ?? new GetOccAvailabilityCatalogContentInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOccAvailabilityCatalogContentArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the availability catalog.
        /// </summary>
        [Input("occAvailabilityCatalogId", required: true)]
        public string OccAvailabilityCatalogId { get; set; } = null!;

        public GetOccAvailabilityCatalogContentArgs()
        {
        }
        public static new GetOccAvailabilityCatalogContentArgs Empty => new GetOccAvailabilityCatalogContentArgs();
    }

    public sealed class GetOccAvailabilityCatalogContentInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the availability catalog.
        /// </summary>
        [Input("occAvailabilityCatalogId", required: true)]
        public Input<string> OccAvailabilityCatalogId { get; set; } = null!;

        public GetOccAvailabilityCatalogContentInvokeArgs()
        {
        }
        public static new GetOccAvailabilityCatalogContentInvokeArgs Empty => new GetOccAvailabilityCatalogContentInvokeArgs();
    }


    [OutputType]
    public sealed class GetOccAvailabilityCatalogContentResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string OccAvailabilityCatalogId;

        [OutputConstructor]
        private GetOccAvailabilityCatalogContentResult(
            string id,

            string occAvailabilityCatalogId)
        {
            Id = id;
            OccAvailabilityCatalogId = occAvailabilityCatalogId;
        }
    }
}
