// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    /// <summary>
    /// This resource provides the Custom Table resource in Oracle Cloud Infrastructure Metering Computation service.
    /// 
    /// Returns the created custom table.
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
    ///     var testCustomTable = new Oci.MeteringComputation.CustomTable("test_custom_table", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         SavedCustomTable = new Oci.MeteringComputation.Inputs.CustomTableSavedCustomTableArgs
    ///         {
    ///             DisplayName = customTableSavedCustomTableDisplayName,
    ///             ColumnGroupBies = customTableSavedCustomTableColumnGroupBy,
    ///             CompartmentDepth = customTableSavedCustomTableCompartmentDepth,
    ///             GroupByTags = new[]
    ///             {
    ///                 new Oci.MeteringComputation.Inputs.CustomTableSavedCustomTableGroupByTagArgs
    ///                 {
    ///                     Key = customTableSavedCustomTableGroupByTagKey,
    ///                     Namespace = customTableSavedCustomTableGroupByTagNamespace,
    ///                     Value = customTableSavedCustomTableGroupByTagValue,
    ///                 },
    ///             },
    ///             RowGroupBies = customTableSavedCustomTableRowGroupBy,
    ///             Version = customTableSavedCustomTableVersion,
    ///         },
    ///         SavedReportId = testSavedReport.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// CustomTables can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:MeteringComputation/customTable:CustomTable test_custom_table "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:MeteringComputation/customTable:CustomTable")]
    public partial class CustomTable : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The compartment OCID.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The custom table for Cost Analysis UI rendering.
        /// </summary>
        [Output("savedCustomTable")]
        public Output<Outputs.CustomTableSavedCustomTable> SavedCustomTable { get; private set; } = null!;

        /// <summary>
        /// The associated saved report OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("savedReportId")]
        public Output<string> SavedReportId { get; private set; } = null!;


        /// <summary>
        /// Create a CustomTable resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public CustomTable(string name, CustomTableArgs args, CustomResourceOptions? options = null)
            : base("oci:MeteringComputation/customTable:CustomTable", name, args ?? new CustomTableArgs(), MakeResourceOptions(options, ""))
        {
        }

        private CustomTable(string name, Input<string> id, CustomTableState? state = null, CustomResourceOptions? options = null)
            : base("oci:MeteringComputation/customTable:CustomTable", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing CustomTable resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static CustomTable Get(string name, Input<string> id, CustomTableState? state = null, CustomResourceOptions? options = null)
        {
            return new CustomTable(name, id, state, options);
        }
    }

    public sealed class CustomTableArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The custom table for Cost Analysis UI rendering.
        /// </summary>
        [Input("savedCustomTable", required: true)]
        public Input<Inputs.CustomTableSavedCustomTableArgs> SavedCustomTable { get; set; } = null!;

        /// <summary>
        /// The associated saved report OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("savedReportId", required: true)]
        public Input<string> SavedReportId { get; set; } = null!;

        public CustomTableArgs()
        {
        }
        public static new CustomTableArgs Empty => new CustomTableArgs();
    }

    public sealed class CustomTableState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The compartment OCID.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The custom table for Cost Analysis UI rendering.
        /// </summary>
        [Input("savedCustomTable")]
        public Input<Inputs.CustomTableSavedCustomTableGetArgs>? SavedCustomTable { get; set; }

        /// <summary>
        /// The associated saved report OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("savedReportId")]
        public Input<string>? SavedReportId { get; set; }

        public CustomTableState()
        {
        }
        public static new CustomTableState Empty => new CustomTableState();
    }
}
