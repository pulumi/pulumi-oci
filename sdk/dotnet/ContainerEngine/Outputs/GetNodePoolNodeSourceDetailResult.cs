// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetNodePoolNodeSourceDetailResult
    {
        /// <summary>
        /// The size of the boot volume in GBs. Minimum value is 50 GB. See [here](https://docs.cloud.oracle.com/en-us/iaas/Content/Block/Concepts/bootvolumes.htm) for max custom boot volume sizing and OS-specific requirements.
        /// </summary>
        public readonly string BootVolumeSizeInGbs;
        /// <summary>
        /// The OCID of the image used to boot the node.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// The source type for the node. Use `IMAGE` when specifying an OCID of an image.
        /// </summary>
        public readonly string SourceType;

        [OutputConstructor]
        private GetNodePoolNodeSourceDetailResult(
            string bootVolumeSizeInGbs,

            string imageId,

            string sourceType)
        {
            BootVolumeSizeInGbs = bootVolumeSizeInGbs;
            ImageId = imageId;
            SourceType = sourceType;
        }
    }
}