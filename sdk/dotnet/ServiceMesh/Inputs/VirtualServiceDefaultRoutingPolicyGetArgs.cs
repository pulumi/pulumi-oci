// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Inputs
{

    public sealed class VirtualServiceDefaultRoutingPolicyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Type of the virtual service routing policy.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public VirtualServiceDefaultRoutingPolicyGetArgs()
        {
        }
        public static new VirtualServiceDefaultRoutingPolicyGetArgs Empty => new VirtualServiceDefaultRoutingPolicyGetArgs();
    }
}