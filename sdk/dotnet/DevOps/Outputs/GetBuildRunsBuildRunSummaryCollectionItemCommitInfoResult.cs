// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildRunsBuildRunSummaryCollectionItemCommitInfoResult
    {
        /// <summary>
        /// Commit hash pertinent to the repository URL and the specified branch.
        /// </summary>
        public readonly string CommitHash;
        /// <summary>
        /// Name of the repository branch.
        /// </summary>
        public readonly string RepositoryBranch;
        /// <summary>
        /// Repository URL.
        /// </summary>
        public readonly string RepositoryUrl;

        [OutputConstructor]
        private GetBuildRunsBuildRunSummaryCollectionItemCommitInfoResult(
            string commitHash,

            string repositoryBranch,

            string repositoryUrl)
        {
            CommitHash = commitHash;
            RepositoryBranch = repositoryBranch;
            RepositoryUrl = repositoryUrl;
        }
    }
}