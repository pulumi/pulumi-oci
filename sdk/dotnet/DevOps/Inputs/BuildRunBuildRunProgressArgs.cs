// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class BuildRunBuildRunProgressArgs : global::Pulumi.ResourceArgs
    {
        [Input("buildPipelineStageRunProgress")]
        private InputMap<object>? _buildPipelineStageRunProgress;

        /// <summary>
        /// Map of stage OCIDs to build pipeline stage run progress model.
        /// </summary>
        public InputMap<object> BuildPipelineStageRunProgress
        {
            get => _buildPipelineStageRunProgress ?? (_buildPipelineStageRunProgress = new InputMap<object>());
            set => _buildPipelineStageRunProgress = value;
        }

        /// <summary>
        /// The time the build run finished. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeFinished")]
        public Input<string>? TimeFinished { get; set; }

        /// <summary>
        /// The time the build run started. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        public BuildRunBuildRunProgressArgs()
        {
        }
        public static new BuildRunBuildRunProgressArgs Empty => new BuildRunBuildRunProgressArgs();
    }
}