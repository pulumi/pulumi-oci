// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlDbSystemAnalyticsClusterResult
    {
        /// <summary>
        /// The number of analytics-processing compute instances, of the specified shape, in the HeatWave cluster.
        /// </summary>
        public readonly int ClusterSize;
        /// <summary>
        /// The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
        /// </summary>
        public readonly string ShapeName;
        /// <summary>
        /// The current state of the DB System.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the DB System was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the DB System was last updated.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMysqlDbSystemAnalyticsClusterResult(
            int clusterSize,

            string shapeName,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            ClusterSize = clusterSize;
            ShapeName = shapeName;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}