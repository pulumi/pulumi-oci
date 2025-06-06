// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerInstances
{
    public static class GetContainerInstanceShapes
    {
        /// <summary>
        /// This data source provides the list of Container Instance Shapes in Oracle Cloud Infrastructure Container Instances service.
        /// 
        /// Lists the shapes that can be used to create container instances.
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
        ///     var testContainerInstanceShapes = Oci.ContainerInstances.GetContainerInstanceShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = containerInstanceShapeAvailabilityDomain,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetContainerInstanceShapesResult> InvokeAsync(GetContainerInstanceShapesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetContainerInstanceShapesResult>("oci:ContainerInstances/getContainerInstanceShapes:getContainerInstanceShapes", args ?? new GetContainerInstanceShapesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Container Instance Shapes in Oracle Cloud Infrastructure Container Instances service.
        /// 
        /// Lists the shapes that can be used to create container instances.
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
        ///     var testContainerInstanceShapes = Oci.ContainerInstances.GetContainerInstanceShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = containerInstanceShapeAvailabilityDomain,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetContainerInstanceShapesResult> Invoke(GetContainerInstanceShapesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetContainerInstanceShapesResult>("oci:ContainerInstances/getContainerInstanceShapes:getContainerInstanceShapes", args ?? new GetContainerInstanceShapesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Container Instance Shapes in Oracle Cloud Infrastructure Container Instances service.
        /// 
        /// Lists the shapes that can be used to create container instances.
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
        ///     var testContainerInstanceShapes = Oci.ContainerInstances.GetContainerInstanceShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = containerInstanceShapeAvailabilityDomain,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetContainerInstanceShapesResult> Invoke(GetContainerInstanceShapesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetContainerInstanceShapesResult>("oci:ContainerInstances/getContainerInstanceShapes:getContainerInstanceShapes", args ?? new GetContainerInstanceShapesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetContainerInstanceShapesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetContainerInstanceShapesFilterArgs>? _filters;
        public List<Inputs.GetContainerInstanceShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetContainerInstanceShapesFilterArgs>());
            set => _filters = value;
        }

        public GetContainerInstanceShapesArgs()
        {
        }
        public static new GetContainerInstanceShapesArgs Empty => new GetContainerInstanceShapesArgs();
    }

    public sealed class GetContainerInstanceShapesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetContainerInstanceShapesFilterInputArgs>? _filters;
        public InputList<Inputs.GetContainerInstanceShapesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetContainerInstanceShapesFilterInputArgs>());
            set => _filters = value;
        }

        public GetContainerInstanceShapesInvokeArgs()
        {
        }
        public static new GetContainerInstanceShapesInvokeArgs Empty => new GetContainerInstanceShapesInvokeArgs();
    }


    [OutputType]
    public sealed class GetContainerInstanceShapesResult
    {
        public readonly string? AvailabilityDomain;
        public readonly string CompartmentId;
        /// <summary>
        /// The list of container_instance_shape_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetContainerInstanceShapesContainerInstanceShapeCollectionResult> ContainerInstanceShapeCollections;
        public readonly ImmutableArray<Outputs.GetContainerInstanceShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetContainerInstanceShapesResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetContainerInstanceShapesContainerInstanceShapeCollectionResult> containerInstanceShapeCollections,

            ImmutableArray<Outputs.GetContainerInstanceShapesFilterResult> filters,

            string id)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ContainerInstanceShapeCollections = containerInstanceShapeCollections;
            Filters = filters;
            Id = id;
        }
    }
}
