// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterEndpointResult
    {
        /// <summary>
        /// The non-native networking Kubernetes API server endpoint.
        /// </summary>
        public readonly string Kubernetes;
        /// <summary>
        /// The private native networking Kubernetes API server endpoint.
        /// </summary>
        public readonly string PrivateEndpoint;
        /// <summary>
        /// The public native networking Kubernetes API server endpoint, if one was requested.
        /// </summary>
        public readonly string PublicEndpoint;
        /// <summary>
        /// The FQDN assigned to the Kubernetes API private endpoint. Example: 'https://yourVcnHostnameEndpoint'
        /// </summary>
        public readonly string VcnHostnameEndpoint;

        [OutputConstructor]
        private GetClustersClusterEndpointResult(
            string kubernetes,

            string privateEndpoint,

            string publicEndpoint,

            string vcnHostnameEndpoint)
        {
            Kubernetes = kubernetes;
            PrivateEndpoint = privateEndpoint;
            PublicEndpoint = publicEndpoint;
            VcnHostnameEndpoint = vcnHostnameEndpoint;
        }
    }
}