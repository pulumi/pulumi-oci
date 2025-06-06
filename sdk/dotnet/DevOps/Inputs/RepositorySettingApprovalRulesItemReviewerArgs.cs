// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class RepositorySettingApprovalRulesItemReviewerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Pull Request reviewer id
        /// </summary>
        [Input("principalId", required: true)]
        public Input<string> PrincipalId { get; set; } = null!;

        /// <summary>
        /// the name of the principal
        /// </summary>
        [Input("principalName")]
        public Input<string>? PrincipalName { get; set; }

        /// <summary>
        /// The state of the principal, it can be active or inactive or suppressed for emails
        /// </summary>
        [Input("principalState")]
        public Input<string>? PrincipalState { get; set; }

        /// <summary>
        /// the type of principal
        /// </summary>
        [Input("principalType")]
        public Input<string>? PrincipalType { get; set; }

        public RepositorySettingApprovalRulesItemReviewerArgs()
        {
        }
        public static new RepositorySettingApprovalRulesItemReviewerArgs Empty => new RepositorySettingApprovalRulesItemReviewerArgs();
    }
}
