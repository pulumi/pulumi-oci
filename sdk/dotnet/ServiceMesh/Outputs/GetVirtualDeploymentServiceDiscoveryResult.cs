// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Outputs
{

    [OutputType]
    public sealed class GetVirtualDeploymentServiceDiscoveryResult
    {
        /// <summary>
        /// The hostname of the virtual deployments.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// Type of service discovery.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetVirtualDeploymentServiceDiscoveryResult(
            string hostname,

            string type)
        {
            Hostname = hostname;
            Type = type;
        }
    }
}