// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentSpecificationRequestPolicyResult
    {
        /// <summary>
        /// Information on how to authenticate incoming requests.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyAuthenticationResult> Authentications;
        /// <summary>
        /// Enable CORS (Cross-Origin-Resource-Sharing) request handling.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyCorResult> Cors;
        /// <summary>
        /// Properties used to configure client mTLS verification when API Consumer makes connection to the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyMutualTlResult> MutualTls;
        /// <summary>
        /// Limit the number of requests that should be handled for the specified window using a specfic key.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyRateLimitingResult> RateLimitings;
        /// <summary>
        /// Usage plan policies for this deployment
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyUsagePlanResult> UsagePlans;

        [OutputConstructor]
        private GetDeploymentSpecificationRequestPolicyResult(
            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyAuthenticationResult> authentications,

            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyCorResult> cors,

            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyMutualTlResult> mutualTls,

            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyRateLimitingResult> rateLimitings,

            ImmutableArray<Outputs.GetDeploymentSpecificationRequestPolicyUsagePlanResult> usagePlans)
        {
            Authentications = authentications;
            Cors = cors;
            MutualTls = mutualTls;
            RateLimitings = rateLimitings;
            UsagePlans = usagePlans;
        }
    }
}