// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetManagedDatabasesDatabaseParameter
    {
        /// <summary>
        /// This data source provides details about a specific Managed Databases Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of database parameters for the specified Managed Database. The parameters are listed in alphabetical order, along with their current values.
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
        ///     var testManagedDatabasesDatabaseParameter = Oci.DatabaseManagement.GetManagedDatabasesDatabaseParameter.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         IsAllowedValuesIncluded = @var.Managed_databases_database_parameter_is_allowed_values_included,
        ///         Name = @var.Managed_databases_database_parameter_name,
        ///         Source = @var.Managed_databases_database_parameter_source,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetManagedDatabasesDatabaseParameterResult> InvokeAsync(GetManagedDatabasesDatabaseParameterArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetManagedDatabasesDatabaseParameterResult>("oci:DatabaseManagement/getManagedDatabasesDatabaseParameter:getManagedDatabasesDatabaseParameter", args ?? new GetManagedDatabasesDatabaseParameterArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Databases Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the list of database parameters for the specified Managed Database. The parameters are listed in alphabetical order, along with their current values.
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
        ///     var testManagedDatabasesDatabaseParameter = Oci.DatabaseManagement.GetManagedDatabasesDatabaseParameter.Invoke(new()
        ///     {
        ///         ManagedDatabaseId = oci_database_management_managed_database.Test_managed_database.Id,
        ///         IsAllowedValuesIncluded = @var.Managed_databases_database_parameter_is_allowed_values_included,
        ///         Name = @var.Managed_databases_database_parameter_name,
        ///         Source = @var.Managed_databases_database_parameter_source,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetManagedDatabasesDatabaseParameterResult> Invoke(GetManagedDatabasesDatabaseParameterInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetManagedDatabasesDatabaseParameterResult>("oci:DatabaseManagement/getManagedDatabasesDatabaseParameter:getManagedDatabasesDatabaseParameter", args ?? new GetManagedDatabasesDatabaseParameterInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagedDatabasesDatabaseParameterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// When true, results include a list of valid values for parameters (if applicable).
        /// </summary>
        [Input("isAllowedValuesIncluded")]
        public bool? IsAllowedValuesIncluded { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public string ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return all parameters that have the text given in their names.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
        /// </summary>
        [Input("source")]
        public string? Source { get; set; }

        public GetManagedDatabasesDatabaseParameterArgs()
        {
        }
        public static new GetManagedDatabasesDatabaseParameterArgs Empty => new GetManagedDatabasesDatabaseParameterArgs();
    }

    public sealed class GetManagedDatabasesDatabaseParameterInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// When true, results include a list of valid values for parameters (if applicable).
        /// </summary>
        [Input("isAllowedValuesIncluded")]
        public Input<bool>? IsAllowedValuesIncluded { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
        /// </summary>
        [Input("managedDatabaseId", required: true)]
        public Input<string> ManagedDatabaseId { get; set; } = null!;

        /// <summary>
        /// A filter to return all parameters that have the text given in their names.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        public GetManagedDatabasesDatabaseParameterInvokeArgs()
        {
        }
        public static new GetManagedDatabasesDatabaseParameterInvokeArgs Empty => new GetManagedDatabasesDatabaseParameterInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagedDatabasesDatabaseParameterResult
    {
        /// <summary>
        /// The name of the Managed Database.
        /// </summary>
        public readonly string DatabaseName;
        /// <summary>
        /// The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or a Non-container Database.
        /// </summary>
        public readonly string DatabaseSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The Oracle Database version.
        /// </summary>
        public readonly string DatabaseVersion;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsAllowedValuesIncluded;
        /// <summary>
        /// An array of DatabaseParameterSummary objects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesDatabaseParameterItemResult> Items;
        public readonly string ManagedDatabaseId;
        /// <summary>
        /// The parameter name.
        /// </summary>
        public readonly string? Name;
        public readonly string? Source;

        [OutputConstructor]
        private GetManagedDatabasesDatabaseParameterResult(
            string databaseName,

            string databaseSubType,

            string databaseType,

            string databaseVersion,

            string id,

            bool? isAllowedValuesIncluded,

            ImmutableArray<Outputs.GetManagedDatabasesDatabaseParameterItemResult> items,

            string managedDatabaseId,

            string? name,

            string? source)
        {
            DatabaseName = databaseName;
            DatabaseSubType = databaseSubType;
            DatabaseType = databaseType;
            DatabaseVersion = databaseVersion;
            Id = id;
            IsAllowedValuesIncluded = isAllowedValuesIncluded;
            Items = items;
            ManagedDatabaseId = managedDatabaseId;
            Name = name;
            Source = source;
        }
    }
}