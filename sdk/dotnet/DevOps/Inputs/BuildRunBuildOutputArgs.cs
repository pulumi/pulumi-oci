// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class BuildRunBuildOutputArgs : global::Pulumi.ResourceArgs
    {
        [Input("artifactOverrideParameters")]
        private InputList<Inputs.BuildRunBuildOutputArtifactOverrideParameterArgs>? _artifactOverrideParameters;

        /// <summary>
        /// Specifies the list of artifact override arguments at the time of deployment.
        /// </summary>
        public InputList<Inputs.BuildRunBuildOutputArtifactOverrideParameterArgs> ArtifactOverrideParameters
        {
            get => _artifactOverrideParameters ?? (_artifactOverrideParameters = new InputList<Inputs.BuildRunBuildOutputArtifactOverrideParameterArgs>());
            set => _artifactOverrideParameters = value;
        }

        [Input("deliveredArtifacts")]
        private InputList<Inputs.BuildRunBuildOutputDeliveredArtifactArgs>? _deliveredArtifacts;

        /// <summary>
        /// Specifies the list of artifacts delivered through the Deliver Artifacts stage.
        /// </summary>
        public InputList<Inputs.BuildRunBuildOutputDeliveredArtifactArgs> DeliveredArtifacts
        {
            get => _deliveredArtifacts ?? (_deliveredArtifacts = new InputList<Inputs.BuildRunBuildOutputDeliveredArtifactArgs>());
            set => _deliveredArtifacts = value;
        }

        [Input("exportedVariables")]
        private InputList<Inputs.BuildRunBuildOutputExportedVariableArgs>? _exportedVariables;

        /// <summary>
        /// Specifies list of exported variables.
        /// </summary>
        public InputList<Inputs.BuildRunBuildOutputExportedVariableArgs> ExportedVariables
        {
            get => _exportedVariables ?? (_exportedVariables = new InputList<Inputs.BuildRunBuildOutputExportedVariableArgs>());
            set => _exportedVariables = value;
        }

        [Input("vulnerabilityAuditSummaryCollections")]
        private InputList<Inputs.BuildRunBuildOutputVulnerabilityAuditSummaryCollectionArgs>? _vulnerabilityAuditSummaryCollections;

        /// <summary>
        /// List of vulnerability audit summary.
        /// </summary>
        public InputList<Inputs.BuildRunBuildOutputVulnerabilityAuditSummaryCollectionArgs> VulnerabilityAuditSummaryCollections
        {
            get => _vulnerabilityAuditSummaryCollections ?? (_vulnerabilityAuditSummaryCollections = new InputList<Inputs.BuildRunBuildOutputVulnerabilityAuditSummaryCollectionArgs>());
            set => _vulnerabilityAuditSummaryCollections = value;
        }

        public BuildRunBuildOutputArgs()
        {
        }
        public static new BuildRunBuildOutputArgs Empty => new BuildRunBuildOutputArgs();
    }
}
