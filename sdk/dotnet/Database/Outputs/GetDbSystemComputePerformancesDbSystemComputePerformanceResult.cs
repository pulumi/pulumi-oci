// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetDbSystemComputePerformancesDbSystemComputePerformanceResult
    {
        /// <summary>
        /// List of Compute performance details for the specified DB system shape.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemComputePerformancesDbSystemComputePerformanceComputePerformanceListResult> ComputePerformanceLists;
        /// <summary>
        /// The shape of the DB system.
        /// </summary>
        public readonly string Shape;

        [OutputConstructor]
        private GetDbSystemComputePerformancesDbSystemComputePerformanceResult(
            ImmutableArray<Outputs.GetDbSystemComputePerformancesDbSystemComputePerformanceComputePerformanceListResult> computePerformanceLists,

            string shape)
        {
            ComputePerformanceLists = computePerformanceLists;
            Shape = shape;
        }
    }
}