// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetImageShape
    {
        /// <summary>
        /// This data source provides details about a specific Image Shape resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Retrieves an image shape compatibility entry.
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
        ///     var testImageShape = Oci.Core.GetImageShape.Invoke(new()
        ///     {
        ///         ImageId = oci_core_image.Test_image.Id,
        ///         ShapeName = oci_core_shape.Test_shape.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetImageShapeResult> InvokeAsync(GetImageShapeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetImageShapeResult>("oci:Core/getImageShape:getImageShape", args ?? new GetImageShapeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Image Shape resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Retrieves an image shape compatibility entry.
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
        ///     var testImageShape = Oci.Core.GetImageShape.Invoke(new()
        ///     {
        ///         ImageId = oci_core_image.Test_image.Id,
        ///         ShapeName = oci_core_shape.Test_shape.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetImageShapeResult> Invoke(GetImageShapeInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetImageShapeResult>("oci:Core/getImageShape:getImageShape", args ?? new GetImageShapeInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetImageShapeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image.
        /// </summary>
        [Input("imageId", required: true)]
        public string ImageId { get; set; } = null!;

        /// <summary>
        /// Shape name.
        /// </summary>
        [Input("shapeName", required: true)]
        public string ShapeName { get; set; } = null!;

        public GetImageShapeArgs()
        {
        }
        public static new GetImageShapeArgs Empty => new GetImageShapeArgs();
    }

    public sealed class GetImageShapeInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image.
        /// </summary>
        [Input("imageId", required: true)]
        public Input<string> ImageId { get; set; } = null!;

        /// <summary>
        /// Shape name.
        /// </summary>
        [Input("shapeName", required: true)]
        public Input<string> ShapeName { get; set; } = null!;

        public GetImageShapeInvokeArgs()
        {
        }
        public static new GetImageShapeInvokeArgs Empty => new GetImageShapeInvokeArgs();
    }


    [OutputType]
    public sealed class GetImageShapeResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// For a flexible image and shape, the amount of memory supported for instances that use this image.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetImageShapeMemoryConstraintResult> MemoryConstraints;
        /// <summary>
        /// OCPU options for an image and shape.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetImageShapeOcpuConstraintResult> OcpuConstraints;
        /// <summary>
        /// The shape name.
        /// </summary>
        public readonly string Shape;
        public readonly string ShapeName;

        [OutputConstructor]
        private GetImageShapeResult(
            string id,

            string imageId,

            ImmutableArray<Outputs.GetImageShapeMemoryConstraintResult> memoryConstraints,

            ImmutableArray<Outputs.GetImageShapeOcpuConstraintResult> ocpuConstraints,

            string shape,

            string shapeName)
        {
            Id = id;
            ImageId = imageId;
            MemoryConstraints = memoryConstraints;
            OcpuConstraints = ocpuConstraints;
            Shape = shape;
            ShapeName = shapeName;
        }
    }
}