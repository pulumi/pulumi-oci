// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class CloudExadataInfrastructureCustomerContactGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The email address used by Oracle to send notifications regarding databases and infrastructure.
        /// </summary>
        [Input("email")]
        public Input<string>? Email { get; set; }

        public CloudExadataInfrastructureCustomerContactGetArgs()
        {
        }
        public static new CloudExadataInfrastructureCustomerContactGetArgs Empty => new CloudExadataInfrastructureCustomerContactGetArgs();
    }
}