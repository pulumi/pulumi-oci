// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabaseSqlTuningSets
    {
        /// <summary>
        /// This data source provides the list of Managed Database Sql Tuning Sets in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the SQL tuning sets for the specified Managed Database.
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
        ///     var testManagedDatabaseSqlTuningSets = Oci.DatabaseManagement.GetManagedDatabaseSqlTuningSets.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         NameContains = @var.Managed_database_sql_tuning_set_name_contains,
        ///         Owner = @var.Managed_database_sql_tuning_set_owner,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabaseSqlTuningSetsResult> InvokeAsync(GetManagedDatabaseSqlTuningSetsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabaseSqlTuningSetsResult>("oci:DatabaseManagement/getManagedDatabaseSqlTuningSets:getManagedDatabaseSqlTuningSets", args ?? new GetManagedDatabaseSqlTuningSetsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Managed Database Sql Tuning Sets in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Lists the SQL tuning sets for the specified Managed Database.
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
        ///     var testManagedDatabaseSqlTuningSets = Oci.DatabaseManagement.GetManagedDatabaseSqlTuningSets.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         NameContains = @var.Managed_database_sql_tuning_set_name_contains,
        ///         Owner = @var.Managed_database_sql_tuning_set_owner,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabaseSqlTuningSetsResult> Invoke(GetManagedDatabaseSqlTuningSetsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabaseSqlTuningSetsResult>("oci:DatabaseManagement/getManagedDatabaseSqlTuningSets:getManagedDatabaseSqlTuningSets", args ?? new GetManagedDatabaseSqlTuningSetsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabaseSqlTuningSetsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetManagedDatabaseSqlTuningSetsFilterArgs>? _filters;
        public List<Inputs.GetManagedDatabaseSqlTuningSetsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagedDatabaseSqlTuningSetsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
        /// </summary>
        [Input("nameContains")]
        public string? NameContains { get; set; }

        /// <summary>
        /// The owner of the SQL tuning set.
        /// </summary>
        [Input("owner")]
        public string? Owner { get; set; }

        public GetManagedDatabaseSqlTuningSetsArgs()
        {
        }
        public static new GetManagedDatabaseSqlTuningSetsArgs Empty => new GetManagedDatabaseSqlTuningSetsArgs();
    }

    public sealed class GetManagedDatabaseSqlTuningSetsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetManagedDatabaseSqlTuningSetsFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagedDatabaseSqlTuningSetsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagedDatabaseSqlTuningSetsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// Allow searching the name of the SQL tuning set by partial matching. The search is case insensitive.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        /// <summary>
        /// The owner of the SQL tuning set.
        /// </summary>
        [Input("owner")]
        public Input<string>? Owner { get; set; }

        public GetManagedDatabaseSqlTuningSetsInvokeArgs()
        {
        }
        public static new GetManagedDatabaseSqlTuningSetsInvokeArgs Empty => new GetManagedDatabaseSqlTuningSetsInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabaseSqlTuningSetsResult
    {
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        public readonly string ManagedDatabaseId;
        public readonly string? NameContains;
        /// <summary>
        /// The owner of the SQL tuning set.
        /// </summary>
        public readonly string? Owner;
        /// <summary>
        /// The list of sql_tuning_set_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionResult> SqlTuningSetCollections;

        [OutputConstructor]
        private GetManagedDatabaseSqlTuningSetsResult(
            ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsFilterResult> filters,

            string id,

            string managedDatabaseId,

            string? nameContains,

            string? owner,

            ImmutableArray<Outputs.GetManagedDatabaseSqlTuningSetsSqlTuningSetCollectionResult> sqlTuningSetCollections)
        {
            Filters = filters;
            Id = id;
            ManagedDatabaseId = managedDatabaseId;
            NameContains = nameContains;
            Owner = owner;
            SqlTuningSetCollections = sqlTuningSetCollections;
        }
    }
}