// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseSqlTuningAdvisorTasksRecommendation
    {
        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Recommendation resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the findings and possible actions for a given object in a SQL tuning task.
        /// The task ID and object ID are used to retrieve the findings and recommendations.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testManagedDatabaseSqlTuningAdvisorTasksRecommendation = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksRecommendation.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs
        ///         {
        ///             ExecutionId = oci_database_management_execution.Test_execution.Id,
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             SqlObjectId = oci_objectstorage_object.Test_object.Id,
        ///             SqlTuningAdvisorTaskId = oci_database_management_sql_tuning_advisor_task.Test_sql_tuning_advisor_task.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult> InvokeAsync(GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult>("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksRecommendation:getManagedDatabaseSqlTuningAdvisorTasksRecommendation", args ?? new GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Recommendation resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the findings and possible actions for a given object in a SQL tuning task.
        /// The task ID and object ID are used to retrieve the findings and recommendations.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testManagedDatabaseSqlTuningAdvisorTasksRecommendation = Output.Create(Oci.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksRecommendation.InvokeAsync(new Oci.DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs
        ///         {
        ///             ExecutionId = oci_database_management_execution.Test_execution.Id,
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             SqlObjectId = oci_objectstorage_object.Test_object.Id,
        ///             SqlTuningAdvisorTaskId = oci_database_management_sql_tuning_advisor_task.Test_sql_tuning_advisor_task.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult> Invoke(GetManagedDatabaseSqlTuningAdvisorTasksRecommendationInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult>("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksRecommendation:getManagedDatabaseSqlTuningAdvisorTasksRecommendation", args ?? new GetManagedDatabaseSqlTuningAdvisorTasksRecommendationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("executionId", required: true)]
        public string ExecutionId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("sqlObjectId", required: true)]
        public string SqlObjectId { get; set; } = null!;

        /// <summary>
        /// The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("sqlTuningAdvisorTaskId", required: true)]
        public string SqlTuningAdvisorTaskId { get; set; } = null!;

        public GetManagedDatabaseSqlTuningAdvisorTasksRecommendationArgs()
        {
        }
    }

    public sealed class GetManagedDatabaseSqlTuningAdvisorTasksRecommendationInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("executionId", required: true)]
        public Input<string> ExecutionId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("sqlObjectId", required: true)]
        public Input<string> SqlObjectId { get; set; } = null!;

        /// <summary>
        /// The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("sqlTuningAdvisorTaskId", required: true)]
        public Input<string> SqlTuningAdvisorTaskId { get; set; } = null!;

        public GetManagedDatabaseSqlTuningAdvisorTasksRecommendationInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult
    {
        public readonly string ExecutionId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of SQL Tuning Advisor recommendations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationItemResult> Items;
        public readonly string ManagedDatabaseId;
        public readonly string SqlObjectId;
        /// <summary>
        /// The unique identifier of the task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string SqlTuningAdvisorTaskId;

        [OutputConstructor]
        private GetManagedDatabaseSqlTuningAdvisorTasksRecommendationResult(
            string executionId,

            string id,

            ImmutableArray<Outputs.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationItemResult> items,

            string managedDatabaseId,

            string sqlObjectId,

            string sqlTuningAdvisorTaskId)
        {
            ExecutionId = executionId;
            Id = id;
            Items = items;
            ManagedDatabaseId = managedDatabaseId;
            SqlObjectId = sqlObjectId;
            SqlTuningAdvisorTaskId = sqlTuningAdvisorTaskId;
        }
    }
}
