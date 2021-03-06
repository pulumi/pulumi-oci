// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDedicatedVmHostInstanceShapes
    {
        /// <summary>
        /// This data source provides the list of Dedicated Vm Host Instance Shapes in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the shapes that can be used to launch a virtual machine instance on a dedicated virtual machine host within the specified compartment.
        /// You can filter the list by compatibility with a specific dedicated virtual machine host shape.
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
        ///         var testDedicatedVmHostInstanceShapes = Output.Create(Oci.Core.GetDedicatedVmHostInstanceShapes.InvokeAsync(new Oci.Core.GetDedicatedVmHostInstanceShapesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AvailabilityDomain = @var.Dedicated_vm_host_instance_shape_availability_domain,
        ///             DedicatedVmHostShape = @var.Dedicated_vm_host_instance_shape_dedicated_vm_host_shape,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDedicatedVmHostInstanceShapesResult> InvokeAsync(GetDedicatedVmHostInstanceShapesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDedicatedVmHostInstanceShapesResult>("oci:Core/getDedicatedVmHostInstanceShapes:getDedicatedVmHostInstanceShapes", args ?? new GetDedicatedVmHostInstanceShapesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Dedicated Vm Host Instance Shapes in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the shapes that can be used to launch a virtual machine instance on a dedicated virtual machine host within the specified compartment.
        /// You can filter the list by compatibility with a specific dedicated virtual machine host shape.
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
        ///         var testDedicatedVmHostInstanceShapes = Output.Create(Oci.Core.GetDedicatedVmHostInstanceShapes.InvokeAsync(new Oci.Core.GetDedicatedVmHostInstanceShapesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AvailabilityDomain = @var.Dedicated_vm_host_instance_shape_availability_domain,
        ///             DedicatedVmHostShape = @var.Dedicated_vm_host_instance_shape_dedicated_vm_host_shape,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDedicatedVmHostInstanceShapesResult> Invoke(GetDedicatedVmHostInstanceShapesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDedicatedVmHostInstanceShapesResult>("oci:Core/getDedicatedVmHostInstanceShapes:getDedicatedVmHostInstanceShapes", args ?? new GetDedicatedVmHostInstanceShapesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDedicatedVmHostInstanceShapesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Dedicated VM host shape name
        /// </summary>
        [Input("dedicatedVmHostShape")]
        public string? DedicatedVmHostShape { get; set; }

        [Input("filters")]
        private List<Inputs.GetDedicatedVmHostInstanceShapesFilterArgs>? _filters;
        public List<Inputs.GetDedicatedVmHostInstanceShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDedicatedVmHostInstanceShapesFilterArgs>());
            set => _filters = value;
        }

        public GetDedicatedVmHostInstanceShapesArgs()
        {
        }
    }

    public sealed class GetDedicatedVmHostInstanceShapesInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Dedicated VM host shape name
        /// </summary>
        [Input("dedicatedVmHostShape")]
        public Input<string>? DedicatedVmHostShape { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDedicatedVmHostInstanceShapesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDedicatedVmHostInstanceShapesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDedicatedVmHostInstanceShapesFilterInputArgs>());
            set => _filters = value;
        }

        public GetDedicatedVmHostInstanceShapesInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDedicatedVmHostInstanceShapesResult
    {
        /// <summary>
        /// The shape's availability domain.
        /// </summary>
        public readonly string? AvailabilityDomain;
        public readonly string CompartmentId;
        /// <summary>
        /// The list of dedicated_vm_host_instance_shapes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShapeResult> DedicatedVmHostInstanceShapes;
        public readonly string? DedicatedVmHostShape;
        public readonly ImmutableArray<Outputs.GetDedicatedVmHostInstanceShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetDedicatedVmHostInstanceShapesResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetDedicatedVmHostInstanceShapesDedicatedVmHostInstanceShapeResult> dedicatedVmHostInstanceShapes,

            string? dedicatedVmHostShape,

            ImmutableArray<Outputs.GetDedicatedVmHostInstanceShapesFilterResult> filters,

            string id)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DedicatedVmHostInstanceShapes = dedicatedVmHostInstanceShapes;
            DedicatedVmHostShape = dedicatedVmHostShape;
            Filters = filters;
            Id = id;
        }
    }
}
