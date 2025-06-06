// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class ContainerInstanceDnsConfig
    {
        /// <summary>
        /// IP address of a name server that the resolver should query, either an IPv4 address (in dot notation), or an IPv6 address in colon (and possibly dot) notation. If null, uses nameservers from subnet dhcpDnsOptions.
        /// </summary>
        public readonly ImmutableArray<string> Nameservers;
        /// <summary>
        /// Options allows certain internal resolver variables to be modified. Options are a list of objects in https://man7.org/linux/man-pages/man5/resolv.conf.5.html. Examples: ["ndots:n", "edns0"].
        /// </summary>
        public readonly ImmutableArray<string> Options;
        /// <summary>
        /// Search list for host-name lookup. If null, we will use searches from subnet dhcpDnsOptios.
        /// </summary>
        public readonly ImmutableArray<string> Searches;

        [OutputConstructor]
        private ContainerInstanceDnsConfig(
            ImmutableArray<string> nameservers,

            ImmutableArray<string> options,

            ImmutableArray<string> searches)
        {
            Nameservers = nameservers;
            Options = options;
            Searches = searches;
        }
    }
}
