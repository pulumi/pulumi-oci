// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerInstances.Outputs
{

    [OutputType]
    public sealed class GetContainerInstanceShapeItemOcpuOptionResult
    {
        /// <summary>
        /// The maximum number of OCPUs.
        /// </summary>
        public readonly double Max;
        /// <summary>
        /// The minimum number of OCPUs.
        /// </summary>
        public readonly double Min;

        [OutputConstructor]
        private GetContainerInstanceShapeItemOcpuOptionResult(
            double max,

            double min)
        {
            Max = max;
            Min = min;
        }
    }
}
