// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement
{
    public static class GetManagedInstanceEventReport
    {
        /// <summary>
        /// This data source provides details about a specific Managed Instance Event Report resource in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Get summary information about events on this instance.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testManagedInstanceEventReport = Oci.OsManagement.GetManagedInstanceEventReport.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         ManagedInstanceId = oci_osmanagement_managed_instance.Test_managed_instance.Id,
        ///         LatestTimestampGreaterThanOrEqualTo = @var.Managed_instance_event_report_latest_timestamp_greater_than_or_equal_to,
        ///         LatestTimestampLessThan = @var.Managed_instance_event_report_latest_timestamp_less_than,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedInstanceEventReportResult> InvokeAsync(GetManagedInstanceEventReportArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedInstanceEventReportResult>("oci:OsManagement/getManagedInstanceEventReport:getManagedInstanceEventReport", args ?? new GetManagedInstanceEventReportArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Instance Event Report resource in Oracle Cloud Infrastructure OS Management service.
        /// 
        /// Get summary information about events on this instance.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testManagedInstanceEventReport = Oci.OsManagement.GetManagedInstanceEventReport.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         ManagedInstanceId = oci_osmanagement_managed_instance.Test_managed_instance.Id,
        ///         LatestTimestampGreaterThanOrEqualTo = @var.Managed_instance_event_report_latest_timestamp_greater_than_or_equal_to,
        ///         LatestTimestampLessThan = @var.Managed_instance_event_report_latest_timestamp_less_than,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedInstanceEventReportResult> Invoke(GetManagedInstanceEventReportInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedInstanceEventReportResult>("oci:OsManagement/getManagedInstanceEventReport:getManagedInstanceEventReport", args ?? new GetManagedInstanceEventReportInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedInstanceEventReportArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// filter event occurrence. Selecting only those last occurred on or after given date in ISO 8601 format Example: 2017-07-14T02:40:00.000Z
        /// </summary>
        [Input("latestTimestampGreaterThanOrEqualTo")]
        public string? LatestTimestampGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// filter event occurrence. Selecting only those last occurred before given date in ISO 8601 format Example: 2017-07-14T02:40:00.000Z
        /// </summary>
        [Input("latestTimestampLessThan")]
        public string? LatestTimestampLessThan { get; set; }

        /// <summary>
        /// Instance Oracle Cloud identifier (ocid)
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public string ManagedInstanceId { get; set; } = null!;

        public GetManagedInstanceEventReportArgs()
        {
        }
        public static new GetManagedInstanceEventReportArgs Empty => new GetManagedInstanceEventReportArgs();
    }

    public sealed class GetManagedInstanceEventReportInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// filter event occurrence. Selecting only those last occurred on or after given date in ISO 8601 format Example: 2017-07-14T02:40:00.000Z
        /// </summary>
        [Input("latestTimestampGreaterThanOrEqualTo")]
        public Input<string>? LatestTimestampGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// filter event occurrence. Selecting only those last occurred before given date in ISO 8601 format Example: 2017-07-14T02:40:00.000Z
        /// </summary>
        [Input("latestTimestampLessThan")]
        public Input<string>? LatestTimestampLessThan { get; set; }

        /// <summary>
        /// Instance Oracle Cloud identifier (ocid)
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public Input<string> ManagedInstanceId { get; set; } = null!;

        public GetManagedInstanceEventReportInvokeArgs()
        {
        }
        public static new GetManagedInstanceEventReportInvokeArgs Empty => new GetManagedInstanceEventReportInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedInstanceEventReportResult
    {
        public readonly string CompartmentId;
        public readonly int Counts;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? LatestTimestampGreaterThanOrEqualTo;
        public readonly string? LatestTimestampLessThan;
        public readonly string ManagedInstanceId;

        [OutputConstructor]
        private GetManagedInstanceEventReportResult(
            string compartmentId,

            int counts,

            string id,

            string? latestTimestampGreaterThanOrEqualTo,

            string? latestTimestampLessThan,

            string managedInstanceId)
        {
            CompartmentId = compartmentId;
            Counts = counts;
            Id = id;
            LatestTimestampGreaterThanOrEqualTo = latestTimestampGreaterThanOrEqualTo;
            LatestTimestampLessThan = latestTimestampLessThan;
            ManagedInstanceId = managedInstanceId;
        }
    }
}