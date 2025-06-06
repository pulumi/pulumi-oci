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
    public sealed class GetDedicatedVmHostShapesDedicatedVmHostShapeResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The name of the dedicated VM host shape. You can enumerate all available shapes by calling [ListDedicatedVmHostShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/dedicatedVmHostShapes).
        /// </summary>
        public readonly string DedicatedVmHostShape;

        [OutputConstructor]
        private GetDedicatedVmHostShapesDedicatedVmHostShapeResult(
            string availabilityDomain,

            string dedicatedVmHostShape)
        {
            AvailabilityDomain = availabilityDomain;
            DedicatedVmHostShape = dedicatedVmHostShape;
        }
    }
}
