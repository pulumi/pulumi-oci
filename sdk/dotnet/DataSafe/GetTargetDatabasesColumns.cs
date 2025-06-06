// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetTargetDatabasesColumns
    {
        /// <summary>
        /// This data source provides the list of Target Databases Columns in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Returns a list of column metadata objects.
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
        ///     var testTargetDatabasesColumns = Oci.DataSafe.GetTargetDatabasesColumns.Invoke(new()
        ///     {
        ///         TargetDatabaseId = testTargetDatabase.Id,
        ///         ColumnNames = targetDatabasesColumnColumnName,
        ///         ColumnNameContains = targetDatabasesColumnColumnNameContains,
        ///         Datatypes = targetDatabasesColumnDatatype,
        ///         SchemaNames = targetDatabasesColumnSchemaName,
        ///         SchemaNameContains = targetDatabasesColumnSchemaNameContains,
        ///         TableNames = testTable.Name,
        ///         TableNameContains = targetDatabasesColumnTableNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetTargetDatabasesColumnsResult> InvokeAsync(GetTargetDatabasesColumnsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetTargetDatabasesColumnsResult>("oci:DataSafe/getTargetDatabasesColumns:getTargetDatabasesColumns", args ?? new GetTargetDatabasesColumnsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Target Databases Columns in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Returns a list of column metadata objects.
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
        ///     var testTargetDatabasesColumns = Oci.DataSafe.GetTargetDatabasesColumns.Invoke(new()
        ///     {
        ///         TargetDatabaseId = testTargetDatabase.Id,
        ///         ColumnNames = targetDatabasesColumnColumnName,
        ///         ColumnNameContains = targetDatabasesColumnColumnNameContains,
        ///         Datatypes = targetDatabasesColumnDatatype,
        ///         SchemaNames = targetDatabasesColumnSchemaName,
        ///         SchemaNameContains = targetDatabasesColumnSchemaNameContains,
        ///         TableNames = testTable.Name,
        ///         TableNameContains = targetDatabasesColumnTableNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTargetDatabasesColumnsResult> Invoke(GetTargetDatabasesColumnsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetTargetDatabasesColumnsResult>("oci:DataSafe/getTargetDatabasesColumns:getTargetDatabasesColumns", args ?? new GetTargetDatabasesColumnsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Target Databases Columns in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Returns a list of column metadata objects.
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
        ///     var testTargetDatabasesColumns = Oci.DataSafe.GetTargetDatabasesColumns.Invoke(new()
        ///     {
        ///         TargetDatabaseId = testTargetDatabase.Id,
        ///         ColumnNames = targetDatabasesColumnColumnName,
        ///         ColumnNameContains = targetDatabasesColumnColumnNameContains,
        ///         Datatypes = targetDatabasesColumnDatatype,
        ///         SchemaNames = targetDatabasesColumnSchemaName,
        ///         SchemaNameContains = targetDatabasesColumnSchemaNameContains,
        ///         TableNames = testTable.Name,
        ///         TableNameContains = targetDatabasesColumnTableNameContains,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetTargetDatabasesColumnsResult> Invoke(GetTargetDatabasesColumnsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetTargetDatabasesColumnsResult>("oci:DataSafe/getTargetDatabasesColumns:getTargetDatabasesColumns", args ?? new GetTargetDatabasesColumnsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetTargetDatabasesColumnsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only items if column name contains a specific string.
        /// </summary>
        [Input("columnNameContains")]
        public string? ColumnNameContains { get; set; }

        [Input("columnNames")]
        private List<string>? _columnNames;

        /// <summary>
        /// A filter to return only a specific column based on column name.
        /// </summary>
        public List<string> ColumnNames
        {
            get => _columnNames ?? (_columnNames = new List<string>());
            set => _columnNames = value;
        }

        [Input("datatypes")]
        private List<string>? _datatypes;

        /// <summary>
        /// A filter to return only items related to specific datatype.
        /// </summary>
        public List<string> Datatypes
        {
            get => _datatypes ?? (_datatypes = new List<string>());
            set => _datatypes = value;
        }

        [Input("filters")]
        private List<Inputs.GetTargetDatabasesColumnsFilterArgs>? _filters;
        public List<Inputs.GetTargetDatabasesColumnsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetTargetDatabasesColumnsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items if schema name contains a specific string.
        /// </summary>
        [Input("schemaNameContains")]
        public string? SchemaNameContains { get; set; }

        [Input("schemaNames")]
        private List<string>? _schemaNames;

        /// <summary>
        /// A filter to return only items related to specific schema name.
        /// </summary>
        public List<string> SchemaNames
        {
            get => _schemaNames ?? (_schemaNames = new List<string>());
            set => _schemaNames = value;
        }

        /// <summary>
        /// A filter to return only items if table name contains a specific string.
        /// </summary>
        [Input("tableNameContains")]
        public string? TableNameContains { get; set; }

        [Input("tableNames")]
        private List<string>? _tableNames;

        /// <summary>
        /// A filter to return only items related to specific table name.
        /// </summary>
        public List<string> TableNames
        {
            get => _tableNames ?? (_tableNames = new List<string>());
            set => _tableNames = value;
        }

        /// <summary>
        /// The OCID of the Data Safe target database.
        /// </summary>
        [Input("targetDatabaseId", required: true)]
        public string TargetDatabaseId { get; set; } = null!;

        public GetTargetDatabasesColumnsArgs()
        {
        }
        public static new GetTargetDatabasesColumnsArgs Empty => new GetTargetDatabasesColumnsArgs();
    }

    public sealed class GetTargetDatabasesColumnsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only items if column name contains a specific string.
        /// </summary>
        [Input("columnNameContains")]
        public Input<string>? ColumnNameContains { get; set; }

        [Input("columnNames")]
        private InputList<string>? _columnNames;

        /// <summary>
        /// A filter to return only a specific column based on column name.
        /// </summary>
        public InputList<string> ColumnNames
        {
            get => _columnNames ?? (_columnNames = new InputList<string>());
            set => _columnNames = value;
        }

        [Input("datatypes")]
        private InputList<string>? _datatypes;

        /// <summary>
        /// A filter to return only items related to specific datatype.
        /// </summary>
        public InputList<string> Datatypes
        {
            get => _datatypes ?? (_datatypes = new InputList<string>());
            set => _datatypes = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetTargetDatabasesColumnsFilterInputArgs>? _filters;
        public InputList<Inputs.GetTargetDatabasesColumnsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetTargetDatabasesColumnsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only items if schema name contains a specific string.
        /// </summary>
        [Input("schemaNameContains")]
        public Input<string>? SchemaNameContains { get; set; }

        [Input("schemaNames")]
        private InputList<string>? _schemaNames;

        /// <summary>
        /// A filter to return only items related to specific schema name.
        /// </summary>
        public InputList<string> SchemaNames
        {
            get => _schemaNames ?? (_schemaNames = new InputList<string>());
            set => _schemaNames = value;
        }

        /// <summary>
        /// A filter to return only items if table name contains a specific string.
        /// </summary>
        [Input("tableNameContains")]
        public Input<string>? TableNameContains { get; set; }

        [Input("tableNames")]
        private InputList<string>? _tableNames;

        /// <summary>
        /// A filter to return only items related to specific table name.
        /// </summary>
        public InputList<string> TableNames
        {
            get => _tableNames ?? (_tableNames = new InputList<string>());
            set => _tableNames = value;
        }

        /// <summary>
        /// The OCID of the Data Safe target database.
        /// </summary>
        [Input("targetDatabaseId", required: true)]
        public Input<string> TargetDatabaseId { get; set; } = null!;

        public GetTargetDatabasesColumnsInvokeArgs()
        {
        }
        public static new GetTargetDatabasesColumnsInvokeArgs Empty => new GetTargetDatabasesColumnsInvokeArgs();
    }


    [OutputType]
    public sealed class GetTargetDatabasesColumnsResult
    {
        public readonly string? ColumnNameContains;
        /// <summary>
        /// Name of the column.
        /// </summary>
        public readonly ImmutableArray<string> ColumnNames;
        /// <summary>
        /// The list of columns.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetDatabasesColumnsColumnResult> Columns;
        public readonly ImmutableArray<string> Datatypes;
        public readonly ImmutableArray<Outputs.GetTargetDatabasesColumnsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? SchemaNameContains;
        /// <summary>
        /// Name of the schema.
        /// </summary>
        public readonly ImmutableArray<string> SchemaNames;
        public readonly string? TableNameContains;
        /// <summary>
        /// Name of the table.
        /// </summary>
        public readonly ImmutableArray<string> TableNames;
        public readonly string TargetDatabaseId;

        [OutputConstructor]
        private GetTargetDatabasesColumnsResult(
            string? columnNameContains,

            ImmutableArray<string> columnNames,

            ImmutableArray<Outputs.GetTargetDatabasesColumnsColumnResult> columns,

            ImmutableArray<string> datatypes,

            ImmutableArray<Outputs.GetTargetDatabasesColumnsFilterResult> filters,

            string id,

            string? schemaNameContains,

            ImmutableArray<string> schemaNames,

            string? tableNameContains,

            ImmutableArray<string> tableNames,

            string targetDatabaseId)
        {
            ColumnNameContains = columnNameContains;
            ColumnNames = columnNames;
            Columns = columns;
            Datatypes = datatypes;
            Filters = filters;
            Id = id;
            SchemaNameContains = schemaNameContains;
            SchemaNames = schemaNames;
            TableNameContains = tableNameContains;
            TableNames = tableNames;
            TargetDatabaseId = targetDatabaseId;
        }
    }
}
