// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain.Outputs
{

    [OutputType]
    public sealed class GetBlockchainPlatformComponentDetailOsnOcpuAllocationParamResult
    {
        /// <summary>
        /// Number of OCPU allocation
        /// </summary>
        public readonly double OcpuAllocationNumber;

        [OutputConstructor]
        private GetBlockchainPlatformComponentDetailOsnOcpuAllocationParamResult(double ocpuAllocationNumber)
        {
            OcpuAllocationNumber = ocpuAllocationNumber;
        }
    }
}
