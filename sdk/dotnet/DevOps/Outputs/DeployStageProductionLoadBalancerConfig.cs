// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class DeployStageProductionLoadBalancerConfig
    {
        /// <summary>
        /// (Updatable) Listen port for the backend server.
        /// </summary>
        public readonly int? BackendPort;
        /// <summary>
        /// (Updatable) Name of the load balancer listener.
        /// </summary>
        public readonly string? ListenerName;
        /// <summary>
        /// (Updatable) The OCID of the load balancer.
        /// </summary>
        public readonly string? LoadBalancerId;
        /// <summary>
        /// The current state of the deployment stage.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private DeployStageProductionLoadBalancerConfig(
            int? backendPort,

            string? listenerName,

            string? loadBalancerId,

            string? state)
        {
            BackendPort = backendPort;
            ListenerName = listenerName;
            LoadBalancerId = loadBalancerId;
            State = state;
        }
    }
}