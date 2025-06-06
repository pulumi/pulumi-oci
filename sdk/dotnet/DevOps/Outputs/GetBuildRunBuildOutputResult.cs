// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildRunBuildOutputResult
    {
        /// <summary>
        /// Specifies the list of artifact override arguments at the time of deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunBuildOutputArtifactOverrideParameterResult> ArtifactOverrideParameters;
        /// <summary>
        /// Specifies the list of artifacts delivered through the Deliver Artifacts stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunBuildOutputDeliveredArtifactResult> DeliveredArtifacts;
        /// <summary>
        /// Specifies list of exported variables.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunBuildOutputExportedVariableResult> ExportedVariables;
        /// <summary>
        /// List of vulnerability audit summary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunBuildOutputVulnerabilityAuditSummaryCollectionResult> VulnerabilityAuditSummaryCollections;

        [OutputConstructor]
        private GetBuildRunBuildOutputResult(
            ImmutableArray<Outputs.GetBuildRunBuildOutputArtifactOverrideParameterResult> artifactOverrideParameters,

            ImmutableArray<Outputs.GetBuildRunBuildOutputDeliveredArtifactResult> deliveredArtifacts,

            ImmutableArray<Outputs.GetBuildRunBuildOutputExportedVariableResult> exportedVariables,

            ImmutableArray<Outputs.GetBuildRunBuildOutputVulnerabilityAuditSummaryCollectionResult> vulnerabilityAuditSummaryCollections)
        {
            ArtifactOverrideParameters = artifactOverrideParameters;
            DeliveredArtifacts = deliveredArtifacts;
            ExportedVariables = exportedVariables;
            VulnerabilityAuditSummaryCollections = vulnerabilityAuditSummaryCollections;
        }
    }
}
