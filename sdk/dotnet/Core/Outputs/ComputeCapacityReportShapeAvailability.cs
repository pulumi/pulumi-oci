// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class ComputeCapacityReportShapeAvailability
    {
        /// <summary>
        /// A flag denoting whether capacity is available.
        /// </summary>
        public readonly string? AvailabilityStatus;
        /// <summary>
        /// The total number of new instances that can be created with the specified shape configuration.
        /// </summary>
        public readonly string? AvailableCount;
        /// <summary>
        /// The fault domain for the capacity report.
        /// 
        /// If you do not specify a fault domain, the capacity report includes information about all fault domains.
        /// </summary>
        public readonly string? FaultDomain;
        /// <summary>
        /// The shape that you want to request a capacity report for. You can enumerate all available shapes by calling [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Shape/ListShapes).
        /// </summary>
        public readonly string InstanceShape;
        /// <summary>
        /// The shape configuration for a shape in a capacity report.
        /// </summary>
        public readonly Outputs.ComputeCapacityReportShapeAvailabilityInstanceShapeConfig? InstanceShapeConfig;

        [OutputConstructor]
        private ComputeCapacityReportShapeAvailability(
            string? availabilityStatus,

            string? availableCount,

            string? faultDomain,

            string instanceShape,

            Outputs.ComputeCapacityReportShapeAvailabilityInstanceShapeConfig? instanceShapeConfig)
        {
            AvailabilityStatus = availabilityStatus;
            AvailableCount = availableCount;
            FaultDomain = faultDomain;
            InstanceShape = instanceShape;
            InstanceShapeConfig = instanceShapeConfig;
        }
    }
}