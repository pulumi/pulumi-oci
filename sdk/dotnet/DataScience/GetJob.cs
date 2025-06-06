// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetJob
    {
        /// <summary>
        /// This data source provides details about a specific Job resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a job.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testJob = Oci.DataScience.GetJob.Invoke(new()
        ///     {
        ///         JobId = testJobOciDatascienceJob.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetJobResult> InvokeAsync(GetJobArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetJobResult>("oci:DataScience/getJob:getJob", args ?? new GetJobArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Job resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a job.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testJob = Oci.DataScience.GetJob.Invoke(new()
        ///     {
        ///         JobId = testJobOciDatascienceJob.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJobResult> Invoke(GetJobInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetJobResult>("oci:DataScience/getJob:getJob", args ?? new GetJobInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Job resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets a job.
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testJob = Oci.DataScience.GetJob.Invoke(new()
        ///     {
        ///         JobId = testJobOciDatascienceJob.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJobResult> Invoke(GetJobInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetJobResult>("oci:DataScience/getJob:getJob", args ?? new GetJobInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetJobArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
        /// </summary>
        [Input("jobId", required: true)]
        public string JobId { get; set; } = null!;

        public GetJobArgs()
        {
        }
        public static new GetJobArgs Empty => new GetJobArgs();
    }

    public sealed class GetJobInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
        /// </summary>
        [Input("jobId", required: true)]
        public Input<string> JobId { get; set; } = null!;

        public GetJobInvokeArgs()
        {
        }
        public static new GetJobInvokeArgs Empty => new GetJobInvokeArgs();
    }


    [OutputType]
    public sealed class GetJobResult
    {
        public readonly string ArtifactContentDisposition;
        public readonly string ArtifactContentLength;
        public readonly string ArtifactContentMd5;
        public readonly string ArtifactLastModified;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the project.
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        public readonly bool DeleteRelatedJobRuns;
        /// <summary>
        /// A short description of the job.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly display name for the resource.
        /// </summary>
        public readonly string DisplayName;
        public readonly bool EmptyArtifact;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
        /// </summary>
        public readonly string Id;
        public readonly string JobArtifact;
        /// <summary>
        /// The job configuration details
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobJobConfigurationDetailResult> JobConfigurationDetails;
        /// <summary>
        /// Environment configuration to capture job runtime dependencies.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobJobEnvironmentConfigurationDetailResult> JobEnvironmentConfigurationDetails;
        public readonly string JobId;
        /// <summary>
        /// The job infrastructure configuration details (shape, block storage, etc.)
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobJobInfrastructureConfigurationDetailResult> JobInfrastructureConfigurationDetails;
        /// <summary>
        /// Logging configuration for resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobJobLogConfigurationDetailResult> JobLogConfigurationDetails;
        /// <summary>
        /// Collection of JobStorageMountConfigurationDetails.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobJobStorageMountConfigurationDetailsListResult> JobStorageMountConfigurationDetailsLists;
        /// <summary>
        /// The state of the job.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate the job with.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// The state of the job.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2020-08-06T21:10:29.41Z
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetJobResult(
            string artifactContentDisposition,

            string artifactContentLength,

            string artifactContentMd5,

            string artifactLastModified,

            string compartmentId,

            string createdBy,

            ImmutableDictionary<string, string> definedTags,

            bool deleteRelatedJobRuns,

            string description,

            string displayName,

            bool emptyArtifact,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string jobArtifact,

            ImmutableArray<Outputs.GetJobJobConfigurationDetailResult> jobConfigurationDetails,

            ImmutableArray<Outputs.GetJobJobEnvironmentConfigurationDetailResult> jobEnvironmentConfigurationDetails,

            string jobId,

            ImmutableArray<Outputs.GetJobJobInfrastructureConfigurationDetailResult> jobInfrastructureConfigurationDetails,

            ImmutableArray<Outputs.GetJobJobLogConfigurationDetailResult> jobLogConfigurationDetails,

            ImmutableArray<Outputs.GetJobJobStorageMountConfigurationDetailsListResult> jobStorageMountConfigurationDetailsLists,

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
            JobEnvironmentConfigurationDetails = jobEnvironmentConfigurationDetails;
            JobId = jobId;
            JobInfrastructureConfigurationDetails = jobInfrastructureConfigurationDetails;
            JobLogConfigurationDetails = jobLogConfigurationDetails;
            JobStorageMountConfigurationDetailsLists = jobStorageMountConfigurationDetailsLists;
            LifecycleDetails = lifecycleDetails;
            ProjectId = projectId;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
