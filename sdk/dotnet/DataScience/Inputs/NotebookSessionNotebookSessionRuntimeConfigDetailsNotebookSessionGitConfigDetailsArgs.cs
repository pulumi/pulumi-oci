// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs : global::Pulumi.ResourceArgs
    {
        [Input("notebookSessionGitRepoConfigCollections")]
        private InputList<Inputs.NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsNotebookSessionGitRepoConfigCollectionArgs>? _notebookSessionGitRepoConfigCollections;

        /// <summary>
        /// (Updatable) A collection of Git repository configurations.
        /// </summary>
        public InputList<Inputs.NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsNotebookSessionGitRepoConfigCollectionArgs> NotebookSessionGitRepoConfigCollections
        {
            get => _notebookSessionGitRepoConfigCollections ?? (_notebookSessionGitRepoConfigCollections = new InputList<Inputs.NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsNotebookSessionGitRepoConfigCollectionArgs>());
            set => _notebookSessionGitRepoConfigCollections = value;
        }

        public NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs()
        {
        }
        public static new NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs Empty => new NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsArgs();
    }
}
