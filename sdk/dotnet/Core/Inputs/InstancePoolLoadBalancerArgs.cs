// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstancePoolLoadBalancerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the backend set on the load balancer to add instances to.
        /// </summary>
        [Input("backendSetName", required: true)]
        public Input<string> BackendSetName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attachment.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
        /// </summary>
        [Input("instancePoolId")]
        public Input<string>? InstancePoolId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to attach to the instance pool.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The port value to use when creating the backend set.
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// (Updatable) The target state for the instance pool update operation (ignored at create time and should not be set). Could be set to RUNNING or STOPPED.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Indicates which VNIC on each instance in the pool should be used to associate with the load balancer. Possible values are "PrimaryVnic" or the displayName of one of the secondary VNICs on the instance configuration that is associated with the instance pool.
        /// </summary>
        [Input("vnicSelection", required: true)]
        public Input<string> VnicSelection { get; set; } = null!;

        public InstancePoolLoadBalancerArgs()
        {
        }
        public static new InstancePoolLoadBalancerArgs Empty => new InstancePoolLoadBalancerArgs();
    }
}
