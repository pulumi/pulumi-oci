// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    public static class GetCustomTable
    {
        /// <summary>
        /// This data source provides details about a specific Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved custom table.
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
        ///         var testCustomTable = Output.Create(Oci.MeteringComputation.GetCustomTable.InvokeAsync(new Oci.MeteringComputation.GetCustomTableArgs
        ///         {
        ///             CustomTableId = oci_metering_computation_custom_table.Test_custom_table.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCustomTableResult> InvokeAsync(GetCustomTableArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCustomTableResult>("oci:MeteringComputation/getCustomTable:getCustomTable", args ?? new GetCustomTableArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved custom table.
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
        ///         var testCustomTable = Output.Create(Oci.MeteringComputation.GetCustomTable.InvokeAsync(new Oci.MeteringComputation.GetCustomTableArgs
        ///         {
        ///             CustomTableId = oci_metering_computation_custom_table.Test_custom_table.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetCustomTableResult> Invoke(GetCustomTableInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetCustomTableResult>("oci:MeteringComputation/getCustomTable:getCustomTable", args ?? new GetCustomTableInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetCustomTableArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The custom table unique OCID.
        /// </summary>
        [Input("customTableId", required: true)]
        public string CustomTableId { get; set; } = null!;

        public GetCustomTableArgs()
        {
        }
    }

    public sealed class GetCustomTableInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The custom table unique OCID.
        /// </summary>
        [Input("customTableId", required: true)]
        public Input<string> CustomTableId { get; set; } = null!;

        public GetCustomTableInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCustomTableResult
    {
        /// <summary>
        /// The custom table compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string CustomTableId;
        /// <summary>
        /// The custom table OCID.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The custom table for Cost Analysis UI rendering.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCustomTableSavedCustomTableResult> SavedCustomTables;
        /// <summary>
        /// The custom table associated saved report OCID.
        /// </summary>
        public readonly string SavedReportId;

        [OutputConstructor]
        private GetCustomTableResult(
            string compartmentId,

            string customTableId,

            string id,

            ImmutableArray<Outputs.GetCustomTableSavedCustomTableResult> savedCustomTables,

            string savedReportId)
        {
            CompartmentId = compartmentId;
            CustomTableId = customTableId;
            Id = id;
            SavedCustomTables = savedCustomTables;
            SavedReportId = savedReportId;
        }
    }
}
