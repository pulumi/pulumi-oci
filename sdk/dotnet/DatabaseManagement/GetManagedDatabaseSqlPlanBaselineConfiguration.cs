// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseSqlPlanBaselineConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline Configuration resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the configuration details of SQL plan baselines for the specified
        /// Managed Database. The details include the settings for the capture and use of
        /// SQL plan baselines, SPM Evolve Advisor task, and SQL Management Base.
        /// 
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
        ///     var testManagedDatabaseSqlPlanBaselineConfiguration = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaselineConfiguration.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineConfigurationOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseSqlPlanBaselineConfigurationResult> InvokeAsync(GetManagedDatabaseSqlPlanBaselineConfigurationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseSqlPlanBaselineConfigurationResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselineConfiguration:getManagedDatabaseSqlPlanBaselineConfiguration", args ?? new GetManagedDatabaseSqlPlanBaselineConfigurationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline Configuration resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the configuration details of SQL plan baselines for the specified
        /// Managed Database. The details include the settings for the capture and use of
        /// SQL plan baselines, SPM Evolve Advisor task, and SQL Management Base.
        /// 
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
        ///     var testManagedDatabaseSqlPlanBaselineConfiguration = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaselineConfiguration.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineConfigurationOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselineConfigurationResult> Invoke(GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselineConfigurationResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselineConfiguration:getManagedDatabaseSqlPlanBaselineConfiguration", args ?? new GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline Configuration resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the configuration details of SQL plan baselines for the specified
        /// Managed Database. The details include the settings for the capture and use of
        /// SQL plan baselines, SPM Evolve Advisor task, and SQL Management Base.
        /// 
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
        ///     var testManagedDatabaseSqlPlanBaselineConfiguration = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaselineConfiguration.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineConfigurationOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselineConfigurationResult> Invoke(GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselineConfigurationResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselineConfiguration:getManagedDatabaseSqlPlanBaselineConfiguration", args ?? new GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseSqlPlanBaselineConfigurationArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The OCID of the Named Credential.
        /// </summary>
        [Input("opcNamedCredentialId")]
        public string? OpcNamedCredentialId { get; set; }

        public GetManagedDatabaseSqlPlanBaselineConfigurationArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselineConfigurationArgs Empty => new GetManagedDatabaseSqlPlanBaselineConfigurationArgs();
    }

    public sealed class GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The OCID of the Named Credential.
        /// </summary>
        [Input("opcNamedCredentialId")]
        public Input<string>? OpcNamedCredentialId { get; set; }

        public GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs Empty => new GetManagedDatabaseSqlPlanBaselineConfigurationInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseSqlPlanBaselineConfigurationResult
    {
        /// <summary>
        /// The capture filters used in automatic initial plan capture.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselineConfigurationAutoCaptureFilterResult> AutoCaptureFilters;
        /// <summary>
        /// The set of parameters used in an SPM evolve task.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselineConfigurationAutoSpmEvolveTaskParameterResult> AutoSpmEvolveTaskParameters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the Automatic SPM Evolve Advisor task is enabled (`true`) or not (`false`).
        /// </summary>
        public readonly bool IsAutoSpmEvolveTaskEnabled;
        /// <summary>
        /// Indicates whether the automatic capture of SQL plan baselines is enabled (`true`) or not (`false`).
        /// </summary>
        public readonly bool IsAutomaticInitialPlanCaptureEnabled;
        /// <summary>
        /// Indicates whether the high frequency Automatic SPM Evolve Advisor task is enabled (`true`) or not (`false`).
        /// </summary>
        public readonly bool IsHighFrequencyAutoSpmEvolveTaskEnabled;
        /// <summary>
        /// Indicates whether the database uses SQL plan baselines (`true`) or not (`false`).
        /// </summary>
        public readonly bool IsSqlPlanBaselinesUsageEnabled;
        public readonly string ManagedDatabaseId;
        public readonly string? OpcNamedCredentialId;
        /// <summary>
        /// The number of weeks to retain unused plans before they are purged.
        /// </summary>
        public readonly int PlanRetentionWeeks;
        /// <summary>
        /// The maximum `SYSAUX` space that can be used for SQL Management Base in MB.
        /// </summary>
        public readonly double SpaceBudgetMb;
        /// <summary>
        /// The maximum percent of `SYSAUX` space that can be used for SQL Management Base.
        /// </summary>
        public readonly double SpaceBudgetPercent;
        /// <summary>
        /// The space used by SQL Management Base in MB.
        /// </summary>
        public readonly double SpaceUsedMb;

        [OutputConstructor]
        private GetManagedDatabaseSqlPlanBaselineConfigurationResult(
            ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselineConfigurationAutoCaptureFilterResult> autoCaptureFilters,

            ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselineConfigurationAutoSpmEvolveTaskParameterResult> autoSpmEvolveTaskParameters,

            string id,

            bool isAutoSpmEvolveTaskEnabled,

            bool isAutomaticInitialPlanCaptureEnabled,

            bool isHighFrequencyAutoSpmEvolveTaskEnabled,

            bool isSqlPlanBaselinesUsageEnabled,

            string managedDatabaseId,

            string? opcNamedCredentialId,

            int planRetentionWeeks,

            double spaceBudgetMb,

            double spaceBudgetPercent,

            double spaceUsedMb)
        {
            AutoCaptureFilters = autoCaptureFilters;
            AutoSpmEvolveTaskParameters = autoSpmEvolveTaskParameters;
            Id = id;
            IsAutoSpmEvolveTaskEnabled = isAutoSpmEvolveTaskEnabled;
            IsAutomaticInitialPlanCaptureEnabled = isAutomaticInitialPlanCaptureEnabled;
            IsHighFrequencyAutoSpmEvolveTaskEnabled = isHighFrequencyAutoSpmEvolveTaskEnabled;
            IsSqlPlanBaselinesUsageEnabled = isSqlPlanBaselinesUsageEnabled;
            ManagedDatabaseId = managedDatabaseId;
            OpcNamedCredentialId = opcNamedCredentialId;
            PlanRetentionWeeks = planRetentionWeeks;
            SpaceBudgetMb = spaceBudgetMb;
            SpaceBudgetPercent = spaceBudgetPercent;
            SpaceUsedMb = spaceUsedMb;
        }
    }
}
