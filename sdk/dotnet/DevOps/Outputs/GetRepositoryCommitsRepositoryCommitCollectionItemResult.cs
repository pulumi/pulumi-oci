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
    public sealed class GetRepositoryCommitsRepositoryCommitCollectionItemResult
    {
        /// <summary>
        /// Email of the author of the repository.
        /// </summary>
        public readonly string AuthorEmail;
        /// <summary>
        /// A filter to return any commits that are pushed by the requested author.
        /// </summary>
        public readonly string AuthorName;
        /// <summary>
        /// Commit hash pointed to by reference name.
        /// </summary>
        public readonly string CommitId;
        /// <summary>
        /// A filter to return any commits that contains the given message.
        /// </summary>
        public readonly string CommitMessage;
        /// <summary>
        /// Email of who creates the commit.
        /// </summary>
        public readonly string CommitterEmail;
        /// <summary>
        /// Name of who creates the commit.
        /// </summary>
        public readonly string CommitterName;
        public readonly ImmutableDictionary<string, object> DefinedTags;
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// An array of parent commit IDs of created commit.
        /// </summary>
        public readonly ImmutableArray<string> ParentCommitIds;
        /// <summary>
        /// The time at which commit was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Tree information for the specified commit.
        /// </summary>
        public readonly string TreeId;

        [OutputConstructor]
        private GetRepositoryCommitsRepositoryCommitCollectionItemResult(
            string authorEmail,

            string authorName,

            string commitId,

            string commitMessage,

            string committerEmail,

            string committerName,

            ImmutableDictionary<string, object> definedTags,

            ImmutableDictionary<string, object> freeformTags,

            ImmutableArray<string> parentCommitIds,

            string timeCreated,

            string treeId)
        {
            AuthorEmail = authorEmail;
            AuthorName = authorName;
            CommitId = commitId;
            CommitMessage = commitMessage;
            CommitterEmail = committerEmail;
            CommitterName = committerName;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            ParentCommitIds = parentCommitIds;
            TimeCreated = timeCreated;
            TreeId = treeId;
        }
    }
}