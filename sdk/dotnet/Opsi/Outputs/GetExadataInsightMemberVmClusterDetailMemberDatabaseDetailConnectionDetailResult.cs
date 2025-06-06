// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailResult
    {
        public readonly string HostName;
        public readonly ImmutableArray<Outputs.GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHostResult> Hosts;
        public readonly int Port;
        public readonly string Protocol;
        public readonly string ServiceName;

        [OutputConstructor]
        private GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailResult(
            string hostName,

            ImmutableArray<Outputs.GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHostResult> hosts,

            int port,

            string protocol,

            string serviceName)
        {
            HostName = hostName;
            Hosts = hosts;
            Port = port;
            Protocol = protocol;
            ServiceName = serviceName;
        }
    }
}
