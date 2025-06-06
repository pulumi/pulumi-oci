// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetVirtualCircuitPublicPrefixesVirtualCircuitPublicPrefixResult
    {
        /// <summary>
        /// Publix IP prefix (CIDR) that the customer specified.
        /// </summary>
        public readonly string CidrBlock;
        /// <summary>
        /// A filter to only return resources that match the given verification state.
        /// 
        /// The state value is case-insensitive.
        /// </summary>
        public readonly string VerificationState;

        [OutputConstructor]
        private GetVirtualCircuitPublicPrefixesVirtualCircuitPublicPrefixResult(
            string cidrBlock,

            string verificationState)
        {
            CidrBlock = cidrBlock;
            VerificationState = verificationState;
        }
    }
}
