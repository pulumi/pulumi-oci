// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetImageShapesImageShapeCompatibilityResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// For a flexible image and shape, the amount of memory supported for instances that use this image.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetImageShapesImageShapeCompatibilityMemoryConstraintResult> MemoryConstraints;
        /// <summary>
        /// OCPU options for an image and shape.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetImageShapesImageShapeCompatibilityOcpuConstraintResult> OcpuConstraints;
        /// <summary>
        /// The shape name.
        /// </summary>
        public readonly string Shape;

        [OutputConstructor]
        private GetImageShapesImageShapeCompatibilityResult(
            string imageId,

            ImmutableArray<Outputs.GetImageShapesImageShapeCompatibilityMemoryConstraintResult> memoryConstraints,

            ImmutableArray<Outputs.GetImageShapesImageShapeCompatibilityOcpuConstraintResult> ocpuConstraints,

            string shape)
        {
            ImageId = imageId;
            MemoryConstraints = memoryConstraints;
            OcpuConstraints = ocpuConstraints;
            Shape = shape;
        }
    }
}
