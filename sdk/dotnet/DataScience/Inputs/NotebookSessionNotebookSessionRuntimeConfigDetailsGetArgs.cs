// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class NotebookSessionNotebookSessionRuntimeConfigDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("customEnvironmentVariables")]
        private InputMap<string>? _customEnvironmentVariables;

        /// <summary>
        /// (Updatable) Custom environment variables for Notebook Session. These key-value pairs will be available for customers in Notebook Sessions.
        /// </summary>
        public InputMap<string> CustomEnvironmentVariables
        {
            get => _customEnvironmentVariables ?? (_customEnvironmentVariables = new InputMap<string>());
            set => _customEnvironmentVariables = value;
        }

        /// <summary>
        /// (Updatable) Git configuration Details.
        /// </summary>
        [Input("notebookSessionGitConfigDetails")]
        public Input<Inputs.NotebookSessionNotebookSessionRuntimeConfigDetailsNotebookSessionGitConfigDetailsGetArgs>? NotebookSessionGitConfigDetails { get; set; }

        public NotebookSessionNotebookSessionRuntimeConfigDetailsGetArgs()
        {
        }
        public static new NotebookSessionNotebookSessionRuntimeConfigDetailsGetArgs Empty => new NotebookSessionNotebookSessionRuntimeConfigDetailsGetArgs();
    }
}
