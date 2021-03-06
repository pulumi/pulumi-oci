// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemCurrentPlacementArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The availability domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
        /// </summary>
        [Input("faultDomain")]
        public Input<string>? FaultDomain { get; set; }

        public MysqlDbSystemCurrentPlacementArgs()
        {
        }
    }
}
