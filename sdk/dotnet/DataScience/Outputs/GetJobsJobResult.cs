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
    public sealed class GetJobsJobResult
    {
        public readonly string ArtifactContentDisposition;
        public readonly string ArtifactContentLength;
        public readonly string ArtifactContentMd5;
        public readonly string ArtifactLastModified;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        public readonly bool DeleteRelatedJobRuns;
        /// <summary>
        /// A short description of the job.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
        /// </summary>
        public readonly string DisplayName;
        public readonly bool EmptyArtifact;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
        /// </summary>
        public readonly string Id;
        public readonly string JobArtifact;
        /// <summary>
        /// The job configuration details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobsJobJobConfigurationDetailResult> JobConfigurationDetails;
        /// <summary>
        /// The job infrastructure configuration details (shape, block storage, etc.)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobsJobJobInfrastructureConfigurationDetailResult> JobInfrastructureConfigurationDetails;
        /// <summary>
        /// Logging configuration for resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobsJobJobLogConfigurationDetailResult> JobLogConfigurationDetails;
        /// <summary>
        /// The state of the job.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetJobsJobResult(
            string artifactContentDisposition,

            string artifactContentLength,

            string artifactContentMd5,

            string artifactLastModified,

            string compartmentId,

            string createdBy,

            ImmutableDictionary<string, object> definedTags,

            bool deleteRelatedJobRuns,

            string description,

            string displayName,

            bool emptyArtifact,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string jobArtifact,

            ImmutableArray<Outputs.GetJobsJobJobConfigurationDetailResult> jobConfigurationDetails,

            ImmutableArray<Outputs.GetJobsJobJobInfrastructureConfigurationDetailResult> jobInfrastructureConfigurationDetails,

            ImmutableArray<Outputs.GetJobsJobJobLogConfigurationDetailResult> jobLogConfigurationDetails,

            string lifecycleDetails,

            string projectId,

            string state,

            string timeCreated)
        {
            ArtifactContentDisposition = artifactContentDisposition;
            ArtifactContentLength = artifactContentLength;
            ArtifactContentMd5 = artifactContentMd5;
            ArtifactLastModified = artifactLastModified;
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DefinedTags = definedTags;
            DeleteRelatedJobRuns = deleteRelatedJobRuns;
            Description = description;
            DisplayName = displayName;
            EmptyArtifact = emptyArtifact;
            FreeformTags = freeformTags;
            Id = id;
            JobArtifact = jobArtifact;
            JobConfigurationDetails = jobConfigurationDetails;
            JobInfrastructureConfigurationDetails = jobInfrastructureConfigurationDetails;
            JobLogConfigurationDetails = jobLogConfigurationDetails;
            LifecycleDetails = lifecycleDetails;
            ProjectId = projectId;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}