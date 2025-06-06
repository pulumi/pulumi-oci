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
    public sealed class ComputeCapacityReservationInstanceReservationConfig
    {
        /// <summary>
        /// (Updatable) The HPC cluster configuration requested when launching instances in a compute capacity reservation.
        /// 
        /// If the parameter is provided, the reservation is created with the HPC island and a list of HPC blocks that you specify. If a list of HPC blocks are missing or not provided, the reservation is created with any HPC blocks in the HPC island that you specify. If the values of HPC island or HPC block that you provide are not valid, an error is returned.
        /// </summary>
        public readonly Outputs.ComputeCapacityReservationInstanceReservationConfigClusterConfig? ClusterConfig;
        /// <summary>
        /// (Updatable) The OCID of the cluster placement group for this instance reservation capacity configuration.
        /// </summary>
        public readonly string? ClusterPlacementGroupId;
        /// <summary>
        /// (Updatable) The fault domain to use for instances created using this capacity configuration. For more information, see [Fault Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm#fault). If you do not specify the fault domain, the capacity is available for an instance that does not specify a fault domain. To change the fault domain for a reservation, delete the reservation and create a new one in the preferred fault domain.
        /// 
        /// To retrieve a list of fault domains, use the `ListFaultDomains` operation in the [Identity and Access Management Service API](https://www.terraform.io/iaas/api/#/en/identity/20160918/).
        /// 
        /// Example: `FAULT-DOMAIN-1`
        /// </summary>
        public readonly string? FaultDomain;
        /// <summary>
        /// (Updatable) The shape requested when launching instances using reserved capacity. The shape determines the number of CPUs, amount of memory, and other resources allocated to the instance. You can list all available shapes by calling [ListComputeCapacityReservationInstanceShapes](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/computeCapacityReservationInstanceShapes/ListComputeCapacityReservationInstanceShapes).
        /// </summary>
        public readonly string InstanceShape;
        /// <summary>
        /// (Updatable) The shape configuration requested when launching instances in a compute capacity reservation.
        /// 
        /// If the parameter is provided, the reservation is created with the resources that you specify. If some properties are missing or the parameter is not provided, the reservation is created with the default configuration values for the `shape` that you specify.
        /// 
        /// Each shape only supports certain configurable values. If the values that you provide are not valid for the specified `shape`, an error is returned.
        /// 
        /// For more information about customizing the resources that are allocated to flexible shapes, see [Flexible Shapes](https://docs.cloud.oracle.com/iaas/Content/Compute/References/computeshapes.htm#flexible).
        /// </summary>
        public readonly Outputs.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig? InstanceShapeConfig;
        /// <summary>
        /// (Updatable) The total number of instances that can be launched from the capacity configuration.
        /// </summary>
        public readonly string ReservedCount;
        /// <summary>
        /// The amount of capacity in use out of the total capacity reserved in this capacity configuration.
        /// </summary>
        public readonly string? UsedCount;

        [OutputConstructor]
        private ComputeCapacityReservationInstanceReservationConfig(
            Outputs.ComputeCapacityReservationInstanceReservationConfigClusterConfig? clusterConfig,

            string? clusterPlacementGroupId,

            string? faultDomain,

            string instanceShape,

            Outputs.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfig? instanceShapeConfig,

            string reservedCount,

            string? usedCount)
        {
            ClusterConfig = clusterConfig;
            ClusterPlacementGroupId = clusterPlacementGroupId;
            FaultDomain = faultDomain;
            InstanceShape = instanceShape;
            InstanceShapeConfig = instanceShapeConfig;
            ReservedCount = reservedCount;
            UsedCount = usedCount;
        }
    }
}
