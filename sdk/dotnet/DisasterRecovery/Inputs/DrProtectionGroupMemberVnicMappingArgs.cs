// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberVnicMappingArgs : global::Pulumi.ResourceArgs
    {
        [Input("destinationNsgIdLists")]
        private InputList<string>? _destinationNsgIdLists;

        /// <summary>
        /// (Updatable) A list of destination region's network security group (NSG) Ids which this VNIC should use.  Example: `[ ocid1.networksecuritygroup.oc1.iad.abcd1, ocid1.networksecuritygroup.oc1.iad.wxyz2 ]`
        /// </summary>
        public InputList<string> DestinationNsgIdLists
        {
            get => _destinationNsgIdLists ?? (_destinationNsgIdLists = new InputList<string>());
            set => _destinationNsgIdLists = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the destination (remote) subnet to which this VNIC should connect.  Example: `ocid1.subnet.oc1.iad.exampleocid2`
        /// </summary>
        [Input("destinationSubnetId")]
        public Input<string>? DestinationSubnetId { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the VNIC.  Example: `ocid1.vnic.oc1.phx.exampleocid1`
        /// </summary>
        [Input("sourceVnicId")]
        public Input<string>? SourceVnicId { get; set; }

        public DrProtectionGroupMemberVnicMappingArgs()
        {
        }
        public static new DrProtectionGroupMemberVnicMappingArgs Empty => new DrProtectionGroupMemberVnicMappingArgs();
    }
}