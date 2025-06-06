// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetRepositorySettingApprovalRuleItemReviewerResult
    {
        /// <summary>
        /// the OCID of the principal
        /// </summary>
        public readonly string PrincipalId;
        /// <summary>
        /// the name of the principal
        /// </summary>
        public readonly string PrincipalName;
        /// <summary>
        /// The state of the principal, it can be active or inactive or suppressed for emails
        /// </summary>
        public readonly string PrincipalState;
        /// <summary>
        /// the type of principal
        /// </summary>
        public readonly string PrincipalType;

        [OutputConstructor]
        private GetRepositorySettingApprovalRuleItemReviewerResult(
            string principalId,

            string principalName,

            string principalState,

            string principalType)
        {
            PrincipalId = principalId;
            PrincipalName = principalName;
            PrincipalState = principalState;
            PrincipalType = principalType;
        }
    }
}
