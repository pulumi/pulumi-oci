// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetDatabaseSecurityConfig
    {
        /// <summary>
        /// This data source provides details about a specific Database Security Config resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a database security configuration by identifier.
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
        ///     var testDatabaseSecurityConfig = Oci.DataSafe.GetDatabaseSecurityConfig.Invoke(new()
        ///     {
        ///         DatabaseSecurityConfigId = testDatabaseSecurityConfigOciDataSafeDatabaseSecurityConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDatabaseSecurityConfigResult> InvokeAsync(GetDatabaseSecurityConfigArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDatabaseSecurityConfigResult>("oci:DataSafe/getDatabaseSecurityConfig:getDatabaseSecurityConfig", args ?? new GetDatabaseSecurityConfigArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Database Security Config resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a database security configuration by identifier.
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
        ///     var testDatabaseSecurityConfig = Oci.DataSafe.GetDatabaseSecurityConfig.Invoke(new()
        ///     {
        ///         DatabaseSecurityConfigId = testDatabaseSecurityConfigOciDataSafeDatabaseSecurityConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseSecurityConfigResult> Invoke(GetDatabaseSecurityConfigInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseSecurityConfigResult>("oci:DataSafe/getDatabaseSecurityConfig:getDatabaseSecurityConfig", args ?? new GetDatabaseSecurityConfigInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Database Security Config resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a database security configuration by identifier.
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
        ///     var testDatabaseSecurityConfig = Oci.DataSafe.GetDatabaseSecurityConfig.Invoke(new()
        ///     {
        ///         DatabaseSecurityConfigId = testDatabaseSecurityConfigOciDataSafeDatabaseSecurityConfig.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDatabaseSecurityConfigResult> Invoke(GetDatabaseSecurityConfigInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDatabaseSecurityConfigResult>("oci:DataSafe/getDatabaseSecurityConfig:getDatabaseSecurityConfig", args ?? new GetDatabaseSecurityConfigInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDatabaseSecurityConfigArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the database security configuration resource.
        /// </summary>
        [Input("databaseSecurityConfigId", required: true)]
        public string DatabaseSecurityConfigId { get; set; } = null!;

        public GetDatabaseSecurityConfigArgs()
        {
        }
        public static new GetDatabaseSecurityConfigArgs Empty => new GetDatabaseSecurityConfigArgs();
    }

    public sealed class GetDatabaseSecurityConfigInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the database security configuration resource.
        /// </summary>
        [Input("databaseSecurityConfigId", required: true)]
        public Input<string> DatabaseSecurityConfigId { get; set; } = null!;

        public GetDatabaseSecurityConfigInvokeArgs()
        {
        }
        public static new GetDatabaseSecurityConfigInvokeArgs Empty => new GetDatabaseSecurityConfigInvokeArgs();
    }


    [OutputType]
    public sealed class GetDatabaseSecurityConfigResult
    {
        /// <summary>
        /// The OCID of the compartment containing the database security config.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DatabaseSecurityConfigId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the database security config.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The display name of the database security config.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the database security config.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the current state of the database security config in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly int RefreshTrigger;
        /// <summary>
        /// The SQL Firewall related configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseSecurityConfigSqlFirewallConfigResult> SqlFirewallConfigs;
        /// <summary>
        /// The current state of the database security config.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The target OCID corresponding to the database security config.
        /// </summary>
        public readonly string TargetId;
        /// <summary>
        /// The time that the database security config was created, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The last date and time the database security config was refreshed, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeLastRefreshed;
        /// <summary>
        /// The date and time the database security configuration was last updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDatabaseSecurityConfigResult(
            string compartmentId,

            string databaseSecurityConfigId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            int refreshTrigger,

            ImmutableArray<Outputs.GetDatabaseSecurityConfigSqlFirewallConfigResult> sqlFirewallConfigs,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string targetId,

            string timeCreated,

            string timeLastRefreshed,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DatabaseSecurityConfigId = databaseSecurityConfigId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            RefreshTrigger = refreshTrigger;
            SqlFirewallConfigs = sqlFirewallConfigs;
            State = state;
            SystemTags = systemTags;
            TargetId = targetId;
            TimeCreated = timeCreated;
            TimeLastRefreshed = timeLastRefreshed;
            TimeUpdated = timeUpdated;
        }
    }
}
