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
    public sealed class GetShapesShapeOcpuOptionResult
    {
        /// <summary>
        /// The maximum allowed percentage of cores enabled.
        /// </summary>
        public readonly double Max;
        /// <summary>
        /// The maximum number of cores available per NUMA node.
        /// </summary>
        public readonly double MaxPerNumaNode;
        /// <summary>
        /// The minimum allowed percentage of cores enabled.
        /// </summary>
        public readonly double Min;

        [OutputConstructor]
        private GetShapesShapeOcpuOptionResult(
            double max,

            double maxPerNumaNode,

            double min)
        {
            Max = max;
            MaxPerNumaNode = maxPerNumaNode;
            Min = min;
        }
    }
}
