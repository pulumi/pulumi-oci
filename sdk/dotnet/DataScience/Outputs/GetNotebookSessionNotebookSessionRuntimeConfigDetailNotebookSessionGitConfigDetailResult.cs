// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetailResult
    {
        /// <summary>
        /// A collection of Git repository configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetailNotebookSessionGitRepoConfigCollectionResult> NotebookSessionGitRepoConfigCollections;

        [OutputConstructor]
        private GetNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetailResult(ImmutableArray<Outputs.GetNotebookSessionNotebookSessionRuntimeConfigDetailNotebookSessionGitConfigDetailNotebookSessionGitRepoConfigCollectionResult> notebookSessionGitRepoConfigCollections)
        {
            NotebookSessionGitRepoConfigCollections = notebookSessionGitRepoConfigCollections;
        }
    }
}