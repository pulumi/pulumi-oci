// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseSqlPlanBaselines
    {
        /// <summary>
        /// This data source provides the list of Managed Database Sql Plan Baselines in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the SQL plan baselines for the specified Managed Database.
        /// </summary>
        public static Task<GetManagedDatabaseSqlPlanBaselinesResult> InvokeAsync(GetManagedDatabaseSqlPlanBaselinesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseSqlPlanBaselinesResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselines:getManagedDatabaseSqlPlanBaselines", args ?? new GetManagedDatabaseSqlPlanBaselinesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Sql Plan Baselines in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the SQL plan baselines for the specified Managed Database.
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselinesResult> Invoke(GetManagedDatabaseSqlPlanBaselinesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselinesResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselines:getManagedDatabaseSqlPlanBaselines", args ?? new GetManagedDatabaseSqlPlanBaselinesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Sql Plan Baselines in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the SQL plan baselines for the specified Managed Database.
        /// </summary>
        public static Output<GetManagedDatabaseSqlPlanBaselinesResult> Invoke(GetManagedDatabaseSqlPlanBaselinesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlPlanBaselinesResult>("oci:DatabaseManagement/getManagedDatabaseSqlPlanBaselines:getManagedDatabaseSqlPlanBaselines", args ?? new GetManagedDatabaseSqlPlanBaselinesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseSqlPlanBaselinesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either accepted or not accepted. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAccepted")]
        public bool? IsAccepted { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either adaptive or not adaptive. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAdaptive")]
        public bool? IsAdaptive { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either auto-purged or not auto-purged. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAutoPurged")]
        public bool? IsAutoPurged { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either enabled or not enabled. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isEnabled")]
        public bool? IsEnabled { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either fixed or not fixed. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isFixed")]
        public bool? IsFixed { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are not executed till now. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isNeverExecuted")]
        public bool? IsNeverExecuted { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that were either reproduced or not reproduced by the optimizer. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isReproduced")]
        public bool? IsReproduced { get; set; }

        [Input("limit")]
        public int? Limit { get; set; }

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
        /// A filter to return all the SQL plan baselines that match the origin.
        /// </summary>
        [Input("origin")]
        public string? Origin { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that match the plan name.
        /// </summary>
        [Input("planName")]
        public string? PlanName { get; set; }

        /// <summary>
        /// A filter to return all the SQL plan baselines for the specified SQL handle.
        /// </summary>
        [Input("sqlHandle")]
        public string? SqlHandle { get; set; }

        /// <summary>
        /// A filter to return all the SQL plan baselines that match the SQL text. By default, the search is case insensitive. To run an exact or case-sensitive search, double-quote the search string. You may also use the '%' symbol as a wildcard.
        /// </summary>
        [Input("sqlText")]
        public string? SqlText { get; set; }

        public GetManagedDatabaseSqlPlanBaselinesArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselinesArgs Empty => new GetManagedDatabaseSqlPlanBaselinesArgs();
    }

    public sealed class GetManagedDatabaseSqlPlanBaselinesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseSqlPlanBaselinesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either accepted or not accepted. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAccepted")]
        public Input<bool>? IsAccepted { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either adaptive or not adaptive. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAdaptive")]
        public Input<bool>? IsAdaptive { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either auto-purged or not auto-purged. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isAutoPurged")]
        public Input<bool>? IsAutoPurged { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either enabled or not enabled. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are either fixed or not fixed. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isFixed")]
        public Input<bool>? IsFixed { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that are not executed till now. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isNeverExecuted")]
        public Input<bool>? IsNeverExecuted { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that were either reproduced or not reproduced by the optimizer. By default, all SQL plan baselines are returned.
        /// </summary>
        [Input("isReproduced")]
        public Input<bool>? IsReproduced { get; set; }

        [Input("limit")]
        public Input<int>? Limit { get; set; }

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
        /// A filter to return all the SQL plan baselines that match the origin.
        /// </summary>
        [Input("origin")]
        public Input<string>? Origin { get; set; }

        /// <summary>
        /// A filter to return only SQL plan baselines that match the plan name.
        /// </summary>
        [Input("planName")]
        public Input<string>? PlanName { get; set; }

        /// <summary>
        /// A filter to return all the SQL plan baselines for the specified SQL handle.
        /// </summary>
        [Input("sqlHandle")]
        public Input<string>? SqlHandle { get; set; }

        /// <summary>
        /// A filter to return all the SQL plan baselines that match the SQL text. By default, the search is case insensitive. To run an exact or case-sensitive search, double-quote the search string. You may also use the '%' symbol as a wildcard.
        /// </summary>
        [Input("sqlText")]
        public Input<string>? SqlText { get; set; }

        public GetManagedDatabaseSqlPlanBaselinesInvokeArgs()
        {
        }
        public static new GetManagedDatabaseSqlPlanBaselinesInvokeArgs Empty => new GetManagedDatabaseSqlPlanBaselinesInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseSqlPlanBaselinesResult
    {
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselinesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsAccepted;
        public readonly bool? IsAdaptive;
        public readonly bool? IsAutoPurged;
        public readonly bool? IsEnabled;
        public readonly bool? IsFixed;
        public readonly bool? IsNeverExecuted;
        public readonly bool? IsReproduced;
        public readonly int? Limit;
        public readonly string ManagedDatabaseId;
        public readonly string? OpcNamedCredentialId;
        /// <summary>
        /// The origin of the SQL plan baseline.
        /// </summary>
        public readonly string? Origin;
        /// <summary>
        /// The unique plan identifier.
        /// </summary>
        public readonly string? PlanName;
        /// <summary>
        /// The unique SQL identifier.
        /// </summary>
        public readonly string? SqlHandle;
        /// <summary>
        /// The list of sql_plan_baseline_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselinesSqlPlanBaselineCollectionResult> SqlPlanBaselineCollections;
        /// <summary>
        /// The SQL text.
        /// </summary>
        public readonly string? SqlText;

        [OutputConstructor]
        private GetManagedDatabaseSqlPlanBaselinesResult(
            ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselinesFilterResult> filters,

            string id,

            bool? isAccepted,

            bool? isAdaptive,

            bool? isAutoPurged,

            bool? isEnabled,

            bool? isFixed,

            bool? isNeverExecuted,

            bool? isReproduced,

            int? limit,

            string managedDatabaseId,

            string? opcNamedCredentialId,

            string? origin,

            string? planName,

            string? sqlHandle,

            ImmutableArray<Outputs.GetManagedDatabaseSqlPlanBaselinesSqlPlanBaselineCollectionResult> sqlPlanBaselineCollections,

            string? sqlText)
        {
            Filters = filters;
            Id = id;
            IsAccepted = isAccepted;
            IsAdaptive = isAdaptive;
            IsAutoPurged = isAutoPurged;
            IsEnabled = isEnabled;
            IsFixed = isFixed;
            IsNeverExecuted = isNeverExecuted;
            IsReproduced = isReproduced;
            Limit = limit;
            ManagedDatabaseId = managedDatabaseId;
            OpcNamedCredentialId = opcNamedCredentialId;
            Origin = origin;
            PlanName = planName;
            SqlHandle = sqlHandle;
            SqlPlanBaselineCollections = sqlPlanBaselineCollections;
            SqlText = sqlText;
        }
    }
}
