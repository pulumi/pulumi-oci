// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class MysqlDbSystemHeatWaveCluster
    {
        /// <summary>
        /// The number of analytics-processing compute instances, of the specified shape, in the HeatWave cluster.
        /// </summary>
        public readonly int? ClusterSize;
        /// <summary>
        /// Lakehouse enabled status for the HeatWave cluster.
        /// </summary>
        public readonly bool? IsLakehouseEnabled;
        /// <summary>
        /// (Updatable) The name of the shape. The shape determines the resources allocated
        /// * CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20190415/ShapeSummary/ListShapes) operation.
        /// </summary>
        public readonly string? ShapeName;
        /// <summary>
        /// (Updatable) The target state for the DB System. Could be set to `ACTIVE` or `INACTIVE`.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the DB System was created.
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The time the DB System was last updated.
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private MysqlDbSystemHeatWaveCluster(
            int? clusterSize,

            bool? isLakehouseEnabled,

            string? shapeName,

            string? state,

            string? timeCreated,

            string? timeUpdated)
        {
            ClusterSize = clusterSize;
            IsLakehouseEnabled = isLakehouseEnabled;
            ShapeName = shapeName;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
