// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp
{
    public static class GetSupportedHostShapes
    {
        /// <summary>
        /// This data source provides the list of Supported Host Shapes in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Lists supported compute shapes for ESXi hosts.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testSupportedHostShapes = Output.Create(Oci.Ocvp.GetSupportedHostShapes.InvokeAsync(new Oci.Ocvp.GetSupportedHostShapesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Name = @var.Supported_host_shape_name,
        ///             SddcType = @var.Supported_host_shape_sddc_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetSupportedHostShapesResult> InvokeAsync(GetSupportedHostShapesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetSupportedHostShapesResult>("oci:Ocvp/getSupportedHostShapes:getSupportedHostShapes", args ?? new GetSupportedHostShapesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Supported Host Shapes in Oracle Cloud Infrastructure Oracle Cloud VMware Solution service.
        /// 
        /// Lists supported compute shapes for ESXi hosts.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testSupportedHostShapes = Output.Create(Oci.Ocvp.GetSupportedHostShapes.InvokeAsync(new Oci.Ocvp.GetSupportedHostShapesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Name = @var.Supported_host_shape_name,
        ///             SddcType = @var.Supported_host_shape_sddc_type,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetSupportedHostShapesResult> Invoke(GetSupportedHostShapesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetSupportedHostShapesResult>("oci:Ocvp/getSupportedHostShapes:getSupportedHostShapes", args ?? new GetSupportedHostShapesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSupportedHostShapesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetSupportedHostShapesFilterArgs>? _filters;
        public List<Inputs.GetSupportedHostShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSupportedHostShapesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given SDDC type exactly.
        /// </summary>
        [Input("sddcType")]
        public string? SddcType { get; set; }

        public GetSupportedHostShapesArgs()
        {
        }
    }

    public sealed class GetSupportedHostShapesInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetSupportedHostShapesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSupportedHostShapesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSupportedHostShapesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given SDDC type exactly.
        /// </summary>
        [Input("sddcType")]
        public Input<string>? SddcType { get; set; }

        public GetSupportedHostShapesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetSupportedHostShapesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetSupportedHostShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of the supported compute shapes for ESXi hosts.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSupportedHostShapesItemResult> Items;
        /// <summary>
        /// The name of the supported compute shape.
        /// </summary>
        public readonly string? Name;
        public readonly string? SddcType;

        [OutputConstructor]
        private GetSupportedHostShapesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetSupportedHostShapesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetSupportedHostShapesItemResult> items,

            string? name,

            string? sddcType)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Items = items;
            Name = name;
            SddcType = sddcType;
        }
    }
}
