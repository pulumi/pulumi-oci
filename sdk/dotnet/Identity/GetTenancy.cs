// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetTenancy
    {
        /// <summary>
        /// This data source provides details about a specific Tenancy resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Get the specified tenancy's information.
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
        ///     var testTenancy = Oci.Identity.GetTenancy.Invoke(new()
        ///     {
        ///         TenancyId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetTenancyResult> InvokeAsync(GetTenancyArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTenancyResult>("oci:Identity/getTenancy:getTenancy", args ?? new GetTenancyArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Tenancy resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Get the specified tenancy's information.
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
        ///     var testTenancy = Oci.Identity.GetTenancy.Invoke(new()
        ///     {
        ///         TenancyId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTenancyResult> Invoke(GetTenancyInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTenancyResult>("oci:Identity/getTenancy:getTenancy", args ?? new GetTenancyInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Tenancy resource in Oracle Cloud Infrastructure Identity service.
        /// 
        /// Get the specified tenancy's information.
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
        ///     var testTenancy = Oci.Identity.GetTenancy.Invoke(new()
        ///     {
        ///         TenancyId = tenancyOcid,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTenancyResult> Invoke(GetTenancyInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetTenancyResult>("oci:Identity/getTenancy:getTenancy", args ?? new GetTenancyInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTenancyArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId", required: true)]
        public string TenancyId { get; set; } = null!;

        public GetTenancyArgs()
        {
        }
        public static new GetTenancyArgs Empty => new GetTenancyArgs();
    }

    public sealed class GetTenancyInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the tenancy.
        /// </summary>
        [Input("tenancyId", required: true)]
        public Input<string> TenancyId { get; set; } = null!;

        public GetTenancyInvokeArgs()
        {
        }
        public static new GetTenancyInvokeArgs Empty => new GetTenancyInvokeArgs();
    }


    [OutputType]
    public sealed class GetTenancyResult
    {
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the tenancy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The region key for the tenancy's home region. For the full list of supported regions, see [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).  Example: `PHX`
        /// </summary>
        public readonly string HomeRegionKey;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the tenancy.
        /// </summary>
        public readonly string Name;
        public readonly string TenancyId;
        /// <summary>
        /// Url which refers to the UPI IDCS compatibility layer endpoint configured for this Tenant's home region.
        /// </summary>
        public readonly string UpiIdcsCompatibilityLayerEndpoint;

        [OutputConstructor]
        private GetTenancyResult(
            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableDictionary<string, string> freeformTags,

            string homeRegionKey,

            string id,

            string name,

            string tenancyId,

            string upiIdcsCompatibilityLayerEndpoint)
        {
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            HomeRegionKey = homeRegionKey;
            Id = id;
            Name = name;
            TenancyId = tenancyId;
            UpiIdcsCompatibilityLayerEndpoint = upiIdcsCompatibilityLayerEndpoint;
        }
    }
}
