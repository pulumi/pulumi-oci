// *** WARNING: this file was generated by pulumi-language-dotnet. ***
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
        ///     var testCustomTable = Oci.MeteringComputation.GetCustomTable.Invoke(new()
        ///     {
        ///         CustomTableId = testCustomTableOciMeteringComputationCustomTable.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetCustomTableResult> InvokeAsync(GetCustomTableArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetCustomTableResult>("oci:MeteringComputation/getCustomTable:getCustomTable", args ?? new GetCustomTableArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved custom table.
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
        ///     var testCustomTable = Oci.MeteringComputation.GetCustomTable.Invoke(new()
        ///     {
        ///         CustomTableId = testCustomTableOciMeteringComputationCustomTable.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCustomTableResult> Invoke(GetCustomTableInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetCustomTableResult>("oci:MeteringComputation/getCustomTable:getCustomTable", args ?? new GetCustomTableInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved custom table.
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
        ///     var testCustomTable = Oci.MeteringComputation.GetCustomTable.Invoke(new()
        ///     {
        ///         CustomTableId = testCustomTableOciMeteringComputationCustomTable.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetCustomTableResult> Invoke(GetCustomTableInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetCustomTableResult>("oci:MeteringComputation/getCustomTable:getCustomTable", args ?? new GetCustomTableInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetCustomTableArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The custom table unique OCID.
        /// </summary>
        [Input("customTableId", required: true)]
        public string CustomTableId { get; set; } = null!;

        public GetCustomTableArgs()
        {
        }
        public static new GetCustomTableArgs Empty => new GetCustomTableArgs();
    }

    public sealed class GetCustomTableInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The custom table unique OCID.
        /// </summary>
        [Input("customTableId", required: true)]
        public Input<string> CustomTableId { get; set; } = null!;

        public GetCustomTableInvokeArgs()
        {
        }
        public static new GetCustomTableInvokeArgs Empty => new GetCustomTableInvokeArgs();
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
