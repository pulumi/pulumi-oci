// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql
{
    public static class GetDbSystem
    {
        /// <summary>
        /// This data source provides details about a specific Db System resource in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Gets a database system by identifier.
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
        ///     var testDbSystem = Oci.Psql.GetDbSystem.Invoke(new()
        ///     {
        ///         DbSystemId = testDbSystemOciPsqlDbSystem.Id,
        ///         ExcludedFields = dbSystemExcludedFields,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDbSystemResult> InvokeAsync(GetDbSystemArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDbSystemResult>("oci:Psql/getDbSystem:getDbSystem", args ?? new GetDbSystemArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db System resource in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Gets a database system by identifier.
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
        ///     var testDbSystem = Oci.Psql.GetDbSystem.Invoke(new()
        ///     {
        ///         DbSystemId = testDbSystemOciPsqlDbSystem.Id,
        ///         ExcludedFields = dbSystemExcludedFields,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbSystemResult> Invoke(GetDbSystemInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbSystemResult>("oci:Psql/getDbSystem:getDbSystem", args ?? new GetDbSystemInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db System resource in Oracle Cloud Infrastructure Psql service.
        /// 
        /// Gets a database system by identifier.
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
        ///     var testDbSystem = Oci.Psql.GetDbSystem.Invoke(new()
        ///     {
        ///         DbSystemId = testDbSystemOciPsqlDbSystem.Id,
        ///         ExcludedFields = dbSystemExcludedFields,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDbSystemResult> Invoke(GetDbSystemInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDbSystemResult>("oci:Psql/getDbSystem:getDbSystem", args ?? new GetDbSystemInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbSystemArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique identifier for the database system.
        /// </summary>
        [Input("dbSystemId", required: true)]
        public string DbSystemId { get; set; } = null!;

        /// <summary>
        /// A filter to exclude database configuration when this query parameter is set to OverrideDbConfig.
        /// </summary>
        [Input("excludedFields")]
        public string? ExcludedFields { get; set; }

        public GetDbSystemArgs()
        {
        }
        public static new GetDbSystemArgs Empty => new GetDbSystemArgs();
    }

    public sealed class GetDbSystemInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique identifier for the database system.
        /// </summary>
        [Input("dbSystemId", required: true)]
        public Input<string> DbSystemId { get; set; } = null!;

        /// <summary>
        /// A filter to exclude database configuration when this query parameter is set to OverrideDbConfig.
        /// </summary>
        [Input("excludedFields")]
        public Input<string>? ExcludedFields { get; set; }

        public GetDbSystemInvokeArgs()
        {
        }
        public static new GetDbSystemInvokeArgs Empty => new GetDbSystemInvokeArgs();
    }


    [OutputType]
    public sealed class GetDbSystemResult
    {
        /// <summary>
        /// The database system administrator username.
        /// </summary>
        public readonly string AdminUsername;
        public readonly string ApplyConfig;
        /// <summary>
        /// target compartment to place a new backup
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration associated with the database system.
        /// </summary>
        public readonly string ConfigId;
        public readonly ImmutableArray<Outputs.GetDbSystemCredentialResult> Credentials;
        public readonly string DbSystemId;
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
        /// A user-friendly display name for the database instance node. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        public readonly string? ExcludedFields;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A unique identifier for the database instance node. Immutable on creation.
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
        public readonly ImmutableArray<Outputs.GetDbSystemInstanceResult> Instances;
        public readonly ImmutableArray<Outputs.GetDbSystemInstancesDetailResult> InstancesDetails;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// PostgreSQL database system management policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemManagementPolicyResult> ManagementPolicies;
        /// <summary>
        /// Network details for the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemNetworkDetailResult> NetworkDetails;
        public readonly ImmutableArray<Outputs.GetDbSystemPatchOperationResult> PatchOperations;
        /// <summary>
        /// The name of the shape for the database instance. Example: `VM.Standard.E4.Flex`
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The source used to restore the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemSourceResult> Sources;
        /// <summary>
        /// The current state of the database system.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Storage details of the database system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbSystemStorageDetailResult> StorageDetails;
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
        private GetDbSystemResult(
            string adminUsername,

            string applyConfig,

            string compartmentId,

            string configId,

            ImmutableArray<Outputs.GetDbSystemCredentialResult> credentials,

            string dbSystemId,

            string dbVersion,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            string? excludedFields,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            int instanceCount,

            int instanceMemorySizeInGbs,

            int instanceOcpuCount,

            ImmutableArray<Outputs.GetDbSystemInstanceResult> instances,

            ImmutableArray<Outputs.GetDbSystemInstancesDetailResult> instancesDetails,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetDbSystemManagementPolicyResult> managementPolicies,

            ImmutableArray<Outputs.GetDbSystemNetworkDetailResult> networkDetails,

            ImmutableArray<Outputs.GetDbSystemPatchOperationResult> patchOperations,

            string shape,

            ImmutableArray<Outputs.GetDbSystemSourceResult> sources,

            string state,

            ImmutableArray<Outputs.GetDbSystemStorageDetailResult> storageDetails,

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
            DbSystemId = dbSystemId;
            DbVersion = dbVersion;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            ExcludedFields = excludedFields;
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
