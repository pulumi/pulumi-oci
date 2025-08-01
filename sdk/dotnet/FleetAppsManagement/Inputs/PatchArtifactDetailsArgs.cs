// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class PatchArtifactDetailsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Patch artifact metadata Details which is common for all platforms.
        /// </summary>
        [Input("artifact")]
        public Input<Inputs.PatchArtifactDetailsArtifactArgs>? Artifact { get; set; }

        [Input("artifacts")]
        private InputList<Inputs.PatchArtifactDetailsArtifactArgs>? _artifacts;

        /// <summary>
        /// (Updatable) Artifacts.
        /// </summary>
        public InputList<Inputs.PatchArtifactDetailsArtifactArgs> Artifacts
        {
            get => _artifacts ?? (_artifacts = new InputList<Inputs.PatchArtifactDetailsArtifactArgs>());
            set => _artifacts = value;
        }

        /// <summary>
        /// (Updatable) Artifact category details.
        /// </summary>
        [Input("category", required: true)]
        public Input<string> Category { get; set; } = null!;

        public PatchArtifactDetailsArgs()
        {
        }
        public static new PatchArtifactDetailsArgs Empty => new PatchArtifactDetailsArgs();
    }
}
