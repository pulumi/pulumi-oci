// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm.Outputs
{

    [OutputType]
    public sealed class GetRemediationRunStagePullRequestPropertyResult
    {
        /// <summary>
        /// Unique identifier for the pull or merge request created in the recommend stage.
        /// </summary>
        public readonly string PullRequestIdentifier;
        /// <summary>
        /// The web link to the pull or merge request created in the recommend stage.
        /// </summary>
        public readonly string PullRequestUrl;

        [OutputConstructor]
        private GetRemediationRunStagePullRequestPropertyResult(
            string pullRequestIdentifier,

            string pullRequestUrl)
        {
            PullRequestIdentifier = pullRequestIdentifier;
            PullRequestUrl = pullRequestUrl;
        }
    }
}
