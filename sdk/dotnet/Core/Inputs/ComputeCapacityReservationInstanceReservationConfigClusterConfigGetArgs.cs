// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class ComputeCapacityReservationInstanceReservationConfigClusterConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the HpcIsland.
        /// </summary>
        [Input("hpcIslandId", required: true)]
        public Input<string> HpcIslandId { get; set; } = null!;

        [Input("networkBlockIds")]
        private InputList<string>? _networkBlockIds;

        /// <summary>
        /// (Updatable) The list of OCID of the network blocks.
        /// </summary>
        public InputList<string> NetworkBlockIds
        {
            get => _networkBlockIds ?? (_networkBlockIds = new InputList<string>());
            set => _networkBlockIds = value;
        }

        public ComputeCapacityReservationInstanceReservationConfigClusterConfigGetArgs()
        {
        }
        public static new ComputeCapacityReservationInstanceReservationConfigClusterConfigGetArgs Empty => new ComputeCapacityReservationInstanceReservationConfigClusterConfigGetArgs();
    }
}