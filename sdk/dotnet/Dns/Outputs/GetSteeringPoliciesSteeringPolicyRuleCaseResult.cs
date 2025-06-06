// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class GetSteeringPoliciesSteeringPolicyRuleCaseResult
    {
        /// <summary>
        /// An array of `SteeringPolicyPriorityAnswerData` objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSteeringPoliciesSteeringPolicyRuleCaseAnswerDataResult> AnswerDatas;
        /// <summary>
        /// An expression that uses conditions at the time of a DNS query to indicate whether a case matches. Conditions may include the geographical location, IP subnet, or ASN the DNS query originated. **Example:** If you have an office that uses the subnet `192.0.2.0/24` you could use a `caseCondition` expression `query.client.address in ('192.0.2.0/24')` to define a case that matches queries from that office.
        /// </summary>
        public readonly string CaseCondition;
        /// <summary>
        /// The number of answers allowed to remain after the limit rule has been processed, keeping only the first of the remaining answers in the list. Example: If the `count` property is set to `2` and four answers remain before the limit rule is processed, only the first two answers in the list will remain after the limit rule has been processed.
        /// </summary>
        public readonly int Count;

        [OutputConstructor]
        private GetSteeringPoliciesSteeringPolicyRuleCaseResult(
            ImmutableArray<Outputs.GetSteeringPoliciesSteeringPolicyRuleCaseAnswerDataResult> answerDatas,

            string caseCondition,

            int count)
        {
            AnswerDatas = answerDatas;
            CaseCondition = caseCondition;
            Count = count;
        }
    }
}
