// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetJobExecutionsStatus
    {
        /// <summary>
        /// This data source provides details about a specific Job Executions Status resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the number of job executions grouped by status for a job, Managed Database, or Database Group in a specific compartment. Only one of the parameters, jobId, managedDatabaseId, or managedDatabaseGroupId should be provided.
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
        ///         var testJobExecutionsStatus = Output.Create(Oci.DatabaseManagement.GetJobExecutionsStatus.InvokeAsync(new Oci.DatabaseManagement.GetJobExecutionsStatusArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             EndTime = @var.Job_executions_status_end_time,
        ///             StartTime = @var.Job_executions_status_start_time,
        ///             Id = @var.Job_executions_status_id,
        ///             ManagedDatabaseGroupId = oci_database_management_managed_database_group.Test_managed_database_group.Id,
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             Name = @var.Job_executions_status_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetJobExecutionsStatusResult> InvokeAsync(GetJobExecutionsStatusArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetJobExecutionsStatusResult>("oci:DatabaseManagement/getJobExecutionsStatus:getJobExecutionsStatus", args ?? new GetJobExecutionsStatusArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Job Executions Status resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the number of job executions grouped by status for a job, Managed Database, or Database Group in a specific compartment. Only one of the parameters, jobId, managedDatabaseId, or managedDatabaseGroupId should be provided.
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
        ///         var testJobExecutionsStatus = Output.Create(Oci.DatabaseManagement.GetJobExecutionsStatus.InvokeAsync(new Oci.DatabaseManagement.GetJobExecutionsStatusArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             EndTime = @var.Job_executions_status_end_time,
        ///             StartTime = @var.Job_executions_status_start_time,
        ///             Id = @var.Job_executions_status_id,
        ///             ManagedDatabaseGroupId = oci_database_management_managed_database_group.Test_managed_database_group.Id,
        ///             ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///             Name = @var.Job_executions_status_name,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetJobExecutionsStatusResult> Invoke(GetJobExecutionsStatusInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetJobExecutionsStatusResult>("oci:DatabaseManagement/getJobExecutionsStatus:getJobExecutionsStatus", args ?? new GetJobExecutionsStatusInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetJobExecutionsStatusArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("endTime", required: true)]
        public string EndTime { get; set; } = null!;

        /// <summary>
        /// The identifier of the resource.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
        /// </summary>
        [Input("managedDatabaseGroupId")]
        public string? ManagedDatabaseGroupId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId")]
        public string? ManagedDatabaseId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("startTime", required: true)]
        public string StartTime { get; set; } = null!;

        public GetJobExecutionsStatusArgs()
        {
        }
    }

    public sealed class GetJobExecutionsStatusInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The end time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("endTime", required: true)]
        public Input<string> EndTime { get; set; } = null!;

        /// <summary>
        /// The identifier of the resource.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
        /// </summary>
        [Input("managedDatabaseGroupId")]
        public Input<string>? ManagedDatabaseGroupId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId")]
        public Input<string>? ManagedDatabaseId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The start time of the time range to retrieve the status summary of job executions in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        [Input("startTime", required: true)]
        public Input<string> StartTime { get; set; } = null!;

        public GetJobExecutionsStatusInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetJobExecutionsStatusResult
    {
        public readonly string CompartmentId;
        public readonly string EndTime;
        public readonly string? Id;
        /// <summary>
        /// A list of JobExecutionsSummary objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJobExecutionsStatusItemResult> Items;
        public readonly string? ManagedDatabaseGroupId;
        public readonly string? ManagedDatabaseId;
        public readonly string? Name;
        public readonly string StartTime;

        [OutputConstructor]
        private GetJobExecutionsStatusResult(
            string compartmentId,

            string endTime,

            string? id,

            ImmutableArray<Outputs.GetJobExecutionsStatusItemResult> items,

            string? managedDatabaseGroupId,

            string? managedDatabaseId,

            string? name,

            string startTime)
        {
            CompartmentId = compartmentId;
            EndTime = endTime;
            Id = id;
            Items = items;
            ManagedDatabaseGroupId = managedDatabaseGroupId;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            StartTime = startTime;
        }
    }
}
