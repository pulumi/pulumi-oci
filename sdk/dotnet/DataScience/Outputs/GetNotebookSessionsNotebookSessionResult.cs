// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetNotebookSessionsNotebookSessionResult
    {
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
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the state of the notebook session.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Details for the notebook session configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailResult> NotebookSessionConfigDetails;
        /// <summary>
        /// Details for the notebook session configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionConfigurationDetailResult> NotebookSessionConfigurationDetails;
        /// <summary>
        /// Notebook Session runtime configuration details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailResult> NotebookSessionRuntimeConfigDetails;
        /// <summary>
        /// Collection of NotebookSessionStorageMountConfigurationDetails.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionStorageMountConfigurationDetailsListResult> NotebookSessionStorageMountConfigurationDetailsLists;
        /// <summary>
        /// The URL to interact with the notebook session.
        /// </summary>
        public readonly string NotebookSessionUrl;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
        /// </summary>
        public readonly string ProjectId;
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: 2019-08-25T21:10:29.41Z
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetNotebookSessionsNotebookSessionResult(
            string compartmentId,

            string createdBy,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailResult> notebookSessionConfigDetails,

            ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionConfigurationDetailResult> notebookSessionConfigurationDetails,

            ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionRuntimeConfigDetailResult> notebookSessionRuntimeConfigDetails,

            ImmutableArray<Outputs.GetNotebookSessionsNotebookSessionNotebookSessionStorageMountConfigurationDetailsListResult> notebookSessionStorageMountConfigurationDetailsLists,

            string notebookSessionUrl,

            string projectId,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NotebookSessionConfigDetails = notebookSessionConfigDetails;
            NotebookSessionConfigurationDetails = notebookSessionConfigurationDetails;
            NotebookSessionRuntimeConfigDetails = notebookSessionRuntimeConfigDetails;
            NotebookSessionStorageMountConfigurationDetailsLists = notebookSessionStorageMountConfigurationDetailsLists;
            NotebookSessionUrl = notebookSessionUrl;
            ProjectId = projectId;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
