// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class AutoScalingConfigurationPolicyDetailsScaleDownConfig
    {
        /// <summary>
        /// (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the size of memory in GBs to add to each node during a scale-up event. This value is not used for nodes with fixed compute shapes.
        /// </summary>
        public readonly int? MemoryStepSize;
        /// <summary>
        /// (Updatable) Metric and threshold details for triggering an autoscale action.
        /// </summary>
        public readonly Outputs.AutoScalingConfigurationPolicyDetailsScaleDownConfigMetric? Metric;
        /// <summary>
        /// (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the minimum memory in GBs each node can be scaled-down to. This value is not used for nodes with fixed compute shapes.
        /// </summary>
        public readonly int? MinMemoryPerNode;
        /// <summary>
        /// (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the minimum number of OCPUs each node can be scaled-down to. This value is not used for nodes with fixed compute shapes.
        /// </summary>
        public readonly int? MinOcpusPerNode;
        /// <summary>
        /// (Updatable) For nodes with [flexible compute shapes](https://docs.cloud.oracle.com/iaas/Content/bigdata/create-cluster.htm#cluster-plan-shape), this value is the number of OCPUs to add to each node during a scale-up event. This value is not used for nodes with fixed compute shapes.
        /// </summary>
        public readonly int? OcpuStepSize;

        [OutputConstructor]
        private AutoScalingConfigurationPolicyDetailsScaleDownConfig(
            int? memoryStepSize,

            Outputs.AutoScalingConfigurationPolicyDetailsScaleDownConfigMetric? metric,

            int? minMemoryPerNode,

            int? minOcpusPerNode,

            int? ocpuStepSize)
        {
            MemoryStepSize = memoryStepSize;
            Metric = metric;
            MinMemoryPerNode = minMemoryPerNode;
            MinOcpusPerNode = minOcpusPerNode;
            OcpuStepSize = ocpuStepSize;
        }
    }
}