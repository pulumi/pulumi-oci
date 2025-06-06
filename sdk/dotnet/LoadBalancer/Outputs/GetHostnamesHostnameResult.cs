// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetHostnamesHostnameResult
    {
        /// <summary>
        /// A virtual hostname. For more information about virtual hostname string construction, see [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm#routing).  Example: `app.example.com`
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the hostnames to retrieve.
        /// </summary>
        public readonly string LoadBalancerId;
        /// <summary>
        /// A friendly name for the hostname resource. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_hostname_001`
        /// </summary>
        public readonly string Name;
        public readonly string State;

        [OutputConstructor]
        private GetHostnamesHostnameResult(
            string hostname,

            string loadBalancerId,

            string name,

            string state)
        {
            Hostname = hostname;
            LoadBalancerId = loadBalancerId;
            Name = name;
            State = state;
        }
    }
}
