// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dblm.Outputs
{

    [OutputType]
    public sealed class GetPatchManagementDatabasesPatchDatabasesCollectionItemResult
    {
        /// <summary>
        /// List of additional patches on database.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatchResult> AdditionalPatches;
        /// <summary>
        /// This is the hashcode representing the list of patches applied.
        /// </summary>
        public readonly string CurrentPatchWatermark;
        /// <summary>
        /// Database ocid.
        /// </summary>
        public readonly string DatabaseId;
        /// <summary>
        /// Database name.
        /// </summary>
        public readonly string DatabaseName;
        /// <summary>
        /// Filter by database type. Possible values Single Instance or RAC.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// For SI, hosted on host and for RAC, host on cluster.
        /// </summary>
        public readonly string HostOrCluster;
        /// <summary>
        /// Image details containing the subscribed image, its status, version, owner and time of creation.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetailResult> ImageDetails;
        /// <summary>
        /// Path to the Oracle home.
        /// </summary>
        public readonly string OracleHomePath;
        /// <summary>
        /// Details of deploy, update and migrate-listener(only for single Instance database) operations for this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetailResult> PatchActivityDetails;
        /// <summary>
        /// Patch Compliance Status
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetailResult> PatchComplianceDetails;
        /// <summary>
        /// Intermediate user to be used for patching, created and maintained by customers. This user requires sudo access to switch as Oracle home owner and root user
        /// </summary>
        public readonly string PatchUser;
        /// <summary>
        /// Database release.
        /// </summary>
        public readonly string Release;
        /// <summary>
        /// Database release full version.
        /// </summary>
        public readonly string ReleaseFullVersion;
        /// <summary>
        /// A filter to return only resources their lifecycleState matches the given lifecycleState.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Path to sudo binary (executable) file
        /// </summary>
        public readonly string SudoFilePath;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Summary of vulnerabilities found in registered resources grouped by severity.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummaryResult> VulnerabilitiesSummaries;

        [OutputConstructor]
        private GetPatchManagementDatabasesPatchDatabasesCollectionItemResult(
            ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemAdditionalPatchResult> additionalPatches,

            string currentPatchWatermark,

            string databaseId,

            string databaseName,

            string databaseType,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string hostOrCluster,

            ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemImageDetailResult> imageDetails,

            string oracleHomePath,

            ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchActivityDetailResult> patchActivityDetails,

            ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemPatchComplianceDetailResult> patchComplianceDetails,

            string patchUser,

            string release,

            string releaseFullVersion,

            string state,

            string sudoFilePath,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetPatchManagementDatabasesPatchDatabasesCollectionItemVulnerabilitiesSummaryResult> vulnerabilitiesSummaries)
        {
            AdditionalPatches = additionalPatches;
            CurrentPatchWatermark = currentPatchWatermark;
            DatabaseId = databaseId;
            DatabaseName = databaseName;
            DatabaseType = databaseType;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            HostOrCluster = hostOrCluster;
            ImageDetails = imageDetails;
            OracleHomePath = oracleHomePath;
            PatchActivityDetails = patchActivityDetails;
            PatchComplianceDetails = patchComplianceDetails;
            PatchUser = patchUser;
            Release = release;
            ReleaseFullVersion = releaseFullVersion;
            State = state;
            SudoFilePath = sudoFilePath;
            SystemTags = systemTags;
            VulnerabilitiesSummaries = vulnerabilitiesSummaries;
        }
    }
}
