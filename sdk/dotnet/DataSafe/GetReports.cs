// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetReports
    {
        /// <summary>
        /// This data source provides the list of Reports in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of all the reports in the compartment. It contains information such as report generation time.
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
        ///         var testReports = Output.Create(Oci.DataSafe.GetReports.InvokeAsync(new Oci.DataSafe.GetReportsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Report_access_level,
        ///             CompartmentIdInSubtree = @var.Report_compartment_id_in_subtree,
        ///             DisplayName = @var.Report_display_name,
        ///             ReportDefinitionId = oci_data_safe_report_definition.Test_report_definition.Id,
        ///             State = @var.Report_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetReportsResult> InvokeAsync(GetReportsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetReportsResult>("oci:DataSafe/getReports:getReports", args ?? new GetReportsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Reports in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of all the reports in the compartment. It contains information such as report generation time.
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
        ///         var testReports = Output.Create(Oci.DataSafe.GetReports.InvokeAsync(new Oci.DataSafe.GetReportsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Report_access_level,
        ///             CompartmentIdInSubtree = @var.Report_compartment_id_in_subtree,
        ///             DisplayName = @var.Report_display_name,
        ///             ReportDefinitionId = oci_data_safe_report_definition.Test_report_definition.Id,
        ///             State = @var.Report_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetReportsResult> Invoke(GetReportsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetReportsResult>("oci:DataSafe/getReports:getReports", args ?? new GetReportsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetReportsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// The name of the report definition to query.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetReportsFilterArgs>? _filters;
        public List<Inputs.GetReportsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetReportsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the report definition to filter the list of reports
        /// </summary>
        [Input("reportDefinitionId")]
        public string? ReportDefinitionId { get; set; }

        /// <summary>
        /// An optional filter to return only resources that match the specified lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetReportsArgs()
        {
        }
    }

    public sealed class GetReportsInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// The name of the report definition to query.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetReportsFilterInputArgs>? _filters;
        public InputList<Inputs.GetReportsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetReportsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The ID of the report definition to filter the list of reports
        /// </summary>
        [Input("reportDefinitionId")]
        public Input<string>? ReportDefinitionId { get; set; }

        /// <summary>
        /// An optional filter to return only resources that match the specified lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetReportsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetReportsResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The OCID of the compartment containing the report.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// Name of the report.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetReportsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of report_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetReportsReportCollectionResult> ReportCollections;
        /// <summary>
        /// The OCID of the report definition.
        /// </summary>
        public readonly string? ReportDefinitionId;
        /// <summary>
        /// The current state of the report.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetReportsResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            ImmutableArray<Outputs.GetReportsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetReportsReportCollectionResult> reportCollections,

            string? reportDefinitionId,

            string? state)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ReportCollections = reportCollections;
            ReportDefinitionId = reportDefinitionId;
            State = state;
        }
    }
}
