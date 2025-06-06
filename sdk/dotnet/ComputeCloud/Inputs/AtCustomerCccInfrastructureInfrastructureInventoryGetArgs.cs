// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud.Inputs
{

    public sealed class AtCustomerCccInfrastructureInfrastructureInventoryGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for capacity storage.
        /// </summary>
        [Input("capacityStorageTrayCount")]
        public Input<int>? CapacityStorageTrayCount { get; set; }

        /// <summary>
        /// The number of compute nodes that are available and usable on the Compute Cloud@Customer infrastructure rack. There is no distinction of compute node type in this information.
        /// </summary>
        [Input("computeNodeCount")]
        public Input<int>? ComputeNodeCount { get; set; }

        /// <summary>
        /// The number of management nodes that are available and in active use on the Compute Cloud@Customer infrastructure rack.
        /// </summary>
        [Input("managementNodeCount")]
        public Input<int>? ManagementNodeCount { get; set; }

        /// <summary>
        /// The number of storage trays in the Compute Cloud@Customer infrastructure rack that are designated for performance storage.
        /// </summary>
        [Input("performanceStorageTrayCount")]
        public Input<int>? PerformanceStorageTrayCount { get; set; }

        /// <summary>
        /// The serial number of the Compute Cloud@Customer infrastructure rack.
        /// </summary>
        [Input("serialNumber")]
        public Input<string>? SerialNumber { get; set; }

        public AtCustomerCccInfrastructureInfrastructureInventoryGetArgs()
        {
        }
        public static new AtCustomerCccInfrastructureInfrastructureInventoryGetArgs Empty => new AtCustomerCccInfrastructureInfrastructureInventoryGetArgs();
    }
}
