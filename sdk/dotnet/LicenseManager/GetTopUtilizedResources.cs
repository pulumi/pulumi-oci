// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LicenseManager
{
    public static class GetTopUtilizedResources
    {
        /// <summary>
        /// This data source provides the list of Top Utilized Resources in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves the top utilized resources for a given compartment.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testTopUtilizedResources = Oci.LicenseManager.GetTopUtilizedResources.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCompartmentIdInSubtree = @var.Top_utilized_resource_is_compartment_id_in_subtree,
        ///         ResourceUnitType = @var.Top_utilized_resource_resource_unit_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetTopUtilizedResourcesResult> InvokeAsync(GetTopUtilizedResourcesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetTopUtilizedResourcesResult>("oci:LicenseManager/getTopUtilizedResources:getTopUtilizedResources", args ?? new GetTopUtilizedResourcesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Top Utilized Resources in Oracle Cloud Infrastructure License Manager service.
        /// 
        /// Retrieves the top utilized resources for a given compartment.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testTopUtilizedResources = Oci.LicenseManager.GetTopUtilizedResources.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         IsCompartmentIdInSubtree = @var.Top_utilized_resource_is_compartment_id_in_subtree,
        ///         ResourceUnitType = @var.Top_utilized_resource_resource_unit_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetTopUtilizedResourcesResult> Invoke(GetTopUtilizedResourcesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetTopUtilizedResourcesResult>("oci:LicenseManager/getTopUtilizedResources:getTopUtilizedResources", args ?? new GetTopUtilizedResourcesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTopUtilizedResourcesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Indicates if the given compartment is the root compartment.
        /// </summary>
        [Input("isCompartmentIdInSubtree")]
        public bool? IsCompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources whose unit matches the given resource unit.
        /// </summary>
        [Input("resourceUnitType")]
        public string? ResourceUnitType { get; set; }

        public GetTopUtilizedResourcesArgs()
        {
        }
        public static new GetTopUtilizedResourcesArgs Empty => new GetTopUtilizedResourcesArgs();
    }

    public sealed class GetTopUtilizedResourcesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Indicates if the given compartment is the root compartment.
        /// </summary>
        [Input("isCompartmentIdInSubtree")]
        public Input<bool>? IsCompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources whose unit matches the given resource unit.
        /// </summary>
        [Input("resourceUnitType")]
        public Input<string>? ResourceUnitType { get; set; }

        public GetTopUtilizedResourcesInvokeArgs()
        {
        }
        public static new GetTopUtilizedResourcesInvokeArgs Empty => new GetTopUtilizedResourcesInvokeArgs();
    }


    [OutputType]
    public sealed class GetTopUtilizedResourcesResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsCompartmentIdInSubtree;
        /// <summary>
        /// The top utilized resource summary collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTopUtilizedResourcesItemResult> Items;
        public readonly string? ResourceUnitType;

        [OutputConstructor]
        private GetTopUtilizedResourcesResult(
            string compartmentId,

            string id,

            bool? isCompartmentIdInSubtree,

            ImmutableArray<Outputs.GetTopUtilizedResourcesItemResult> items,

            string? resourceUnitType)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsCompartmentIdInSubtree = isCompartmentIdInSubtree;
            Items = items;
            ResourceUnitType = resourceUnitType;
        }
    }
}