// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserResult
    {
        /// <summary>
        /// Risk Level
        /// </summary>
        public readonly string RiskLevel;
        /// <summary>
        /// The risk score pertaining to the user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreResult> RiskScores;

        [OutputConstructor]
        private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserResult(
            string riskLevel,

            ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionadaptiveUserRiskScoreResult> riskScores)
        {
            RiskLevel = riskLevel;
            RiskScores = riskScores;
        }
    }
}