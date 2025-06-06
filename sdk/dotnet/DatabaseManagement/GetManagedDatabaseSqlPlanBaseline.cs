// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseSqlPlanBaseline
    {
        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the SQL plan baseline details for the specified planName.
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
        ///     var testManagedDatabaseSqlPlanBaseline = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaseline.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         PlanName = managedDatabaseSqlPlanBaselinePlanName,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagedDatabaseSqlPlanBaselineResult> InvokeAsync(GetManagedDatabaseSqlPlanBaselineArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseSqlPlanBaselineResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaseline:getManagedDatabaseSqlPlanBaseline", args ?? new GetManagedDatabaseSqlPlanBaselineArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the SQL plan baseline details for the specified planName.
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
        ///     var testManagedDatabaseSqlPlanBaseline = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaseline.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         PlanName = managedDatabaseSqlPlanBaselinePlanName,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselineResult> Invoke(GetManagedDatabaseSqlPlanBaselineInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselineResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaseline:getManagedDatabaseSqlPlanBaseline", args ?? new GetManagedDatabaseSqlPlanBaselineInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Plan Baseline resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the SQL plan baseline details for the specified planName.
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
        ///     var testManagedDatabaseSqlPlanBaseline = Oci.DatabaseManagement.GetManagedDatabaseSqlPlanBaseline.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = testManagedDatabase.Id,
        ///         PlanName = managedDatabaseSqlPlanBaselinePlanName,
        ///         OpcNamedCredentialId = managedDatabaseSqlPlanBaselineOpcNamedCredentialId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselineResult> Invoke(GetManagedDatabaseSqlPlanBaselineInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselineResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaseline:getManagedDatabaseSqlPlanBaseline", args ?? new GetManagedDatabaseSqlPlanBaselineInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseSqlPlanBaselineArgs : global::Pulumi.InvokeArgs
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

        /// <summary>
        /// The plan name of the SQL plan baseline.
        /// </summary>
        [Input("planName", required: true)]
        public string PlanName { get; set; } = null!;

        public GetManagedDatabaseSqlPlanBaselineArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselineArgs Empty => new GetManagedDatabaseSqlPlanBaselineArgs();
    }

    public sealed class GetManagedDatabaseSqlPlanBaselineInvokeArgs : global::Pulumi.InvokeArgs
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

        /// <summary>
        /// The plan name of the SQL plan baseline.
        /// </summary>
        [Input("planName", required: true)]
        public Input<string> PlanName { get; set; } = null!;

        public GetManagedDatabaseSqlPlanBaselineInvokeArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselineInvokeArgs Empty => new GetManagedDatabaseSqlPlanBaselineInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseSqlPlanBaselineResult
    {
        /// <summary>
        /// Indicates whether the plan baseline is accepted (`YES`) or not (`NO`).
        /// </summary>
        public readonly string Accepted;
        /// <summary>
        /// The application action.
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// Indicates whether a plan that is automatically captured by SQL plan management is marked adaptive or not.
        /// </summary>
        public readonly string Adaptive;
        /// <summary>
        /// Indicates whether the plan baseline is auto-purged (`YES`) or not (`NO`).
        /// </summary>
        public readonly string AutoPurge;
        /// <summary>
        /// Indicates whether the plan baseline is enabled (`YES`) or disabled (`NO`).
        /// </summary>
        public readonly string Enabled;
        /// <summary>
        /// The execution plan for the SQL statement.
        /// </summary>
        public readonly string ExecutionPlan;
        /// <summary>
        /// Indicates whether the plan baseline is fixed (`YES`) or not (`NO`).
        /// </summary>
        public readonly string Fixed;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The application module name.
        /// </summary>
        public readonly string Module;
        public readonly string? OpcNamedCredentialId;
        /// <summary>
        /// The origin of the SQL plan baseline.
        /// </summary>
        public readonly string Origin;
        /// <summary>
        /// The unique plan identifier.
        /// </summary>
        public readonly string PlanName;
        /// <summary>
        /// Indicates whether the optimizer was able to reproduce the plan (`YES`) or not (`NO`). The value is set to `YES` when a plan is initially added to the plan baseline.
        /// </summary>
        public readonly string Reproduced;
        /// <summary>
        /// The unique SQL identifier.
        /// </summary>
        public readonly string SqlHandle;
        /// <summary>
        /// The SQL text.
        /// </summary>
        public readonly string SqlText;
        /// <summary>
        /// The date and time when the plan baseline was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time when the plan baseline was last executed.
        /// </summary>
        public readonly string TimeLastExecuted;
        /// <summary>
        /// The date and time when the plan baseline was last modified.
        /// </summary>
        public readonly string TimeLastModified;

        [OutputConstructor]
        private GetManagedDatabaseSqlPlanBaselineResult(
            string accepted,

            string action,

            string adaptive,

            string autoPurge,

            string enabled,

            string executionPlan,

            string @fixed,

            string id,

            string managedDatabaseId,

            string module,

            string? opcNamedCredentialId,

            string origin,

            string planName,

            string reproduced,

            string sqlHandle,

            string sqlText,

            string timeCreated,

            string timeLastExecuted,

            string timeLastModified)
        {
            Accepted = accepted;
            Action = action;
            Adaptive = adaptive;
            AutoPurge = autoPurge;
            Enabled = enabled;
            ExecutionPlan = executionPlan;
            Fixed = @fixed;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            Module = module;
            OpcNamedCredentialId = opcNamedCredentialId;
            Origin = origin;
            PlanName = planName;
            Reproduced = reproduced;
            SqlHandle = sqlHandle;
            SqlText = sqlText;
            TimeCreated = timeCreated;
            TimeLastExecuted = timeLastExecuted;
            TimeLastModified = timeLastModified;
        }
    }
}
