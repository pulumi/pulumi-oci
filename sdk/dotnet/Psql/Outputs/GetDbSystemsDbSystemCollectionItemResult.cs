// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql.Outputs
{

    [OutputType]
    public sealed class GetDbSystemsDbSystemCollectionItemResult
    {
        /// <summary>
        /// The database system administrator username.
        /// </summary>
        public readonly string AdminUsername;
        public readonly string ApplyConfig;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration associated with the database system.
        /// </summary>
        public readonly string ConfigId;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemCredentialResult> Credentials;
        /// <summary>
        /// The major and minor versions of the database system software.
        /// </summary>
        public readonly string DbVersion;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Description of the database instance node.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A unique identifier for the database system.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Count of instances, or nodes, in the database system.
        /// </summary>
        public readonly int InstanceCount;
        /// <summary>
        /// The total amount of memory available to each database instance node, in gigabytes.
        /// </summary>
        public readonly int InstanceMemorySizeInGbs;
        /// <summary>
        /// The total number of OCPUs available to each database instance node.
        /// </summary>
        public readonly int InstanceOcpuCount;
        /// <summary>
        /// The list of instances, or nodes, in the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemInstanceResult> Instances;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemInstancesDetailResult> InstancesDetails;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// PostgreSQL database system management policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemManagementPolicyResult> ManagementPolicies;
        /// <summary>
        /// Network details for the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemNetworkDetailResult> NetworkDetails;
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemPatchOperationResult> PatchOperations;
        /// <summary>
        /// The name of the shape for the database instance. Example: `VM.Standard.E4.Flex`
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The source used to restore the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemSourceResult> Sources;
        /// <summary>
        /// A filter to return only resources if their `lifecycleState` matches the given `lifecycleState`.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Storage details of the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemStorageDetailResult> StorageDetails;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Type of the database system.
        /// </summary>
        public readonly string SystemType;
        /// <summary>
        /// The date and time that the database system was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time that the database system was updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDbSystemsDbSystemCollectionItemResult(
            string adminUsername,

            string applyConfig,

            string compartmentId,

            string configId,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemCredentialResult> credentials,

            string dbVersion,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            int instanceCount,

            int instanceMemorySizeInGbs,

            int instanceOcpuCount,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemInstanceResult> instances,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemInstancesDetailResult> instancesDetails,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemManagementPolicyResult> managementPolicies,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemNetworkDetailResult> networkDetails,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemPatchOperationResult> patchOperations,

            string shape,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemSourceResult> sources,

            string state,

            ImmutableArray<Outputs.GetDbSystemsDbSystemCollectionItemStorageDetailResult> storageDetails,

            ImmutableDictionary<string, string> systemTags,

            string systemType,

            string timeCreated,

            string timeUpdated)
        {
            AdminUsername = adminUsername;
            ApplyConfig = applyConfig;
            CompartmentId = compartmentId;
            ConfigId = configId;
            Credentials = credentials;
            DbVersion = dbVersion;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InstanceCount = instanceCount;
            InstanceMemorySizeInGbs = instanceMemorySizeInGbs;
            InstanceOcpuCount = instanceOcpuCount;
            Instances = instances;
            InstancesDetails = instancesDetails;
            LifecycleDetails = lifecycleDetails;
            ManagementPolicies = managementPolicies;
            NetworkDetails = networkDetails;
            PatchOperations = patchOperations;
            Shape = shape;
            Sources = sources;
            State = state;
            StorageDetails = storageDetails;
            SystemTags = systemTags;
            SystemType = systemType;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
