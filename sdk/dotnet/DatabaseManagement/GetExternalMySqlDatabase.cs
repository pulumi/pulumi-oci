// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalMySqlDatabase
    {
        /// <summary>
        /// This data source provides details about a specific External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Retrieves the external MySQL database information.
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
        ///     var testExternalMySqlDatabase = Oci.DatabaseManagement.GetExternalMySqlDatabase.Invoke(new()
        ///     {
        ///         ExternalMySqlDatabaseId = testExternalMySqlDatabaseOciDatabaseManagementExternalMySqlDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalMySqlDatabaseResult> InvokeAsync(GetExternalMySqlDatabaseArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalMySqlDatabaseResult>("oci:DatabaseManagement/getExternalMySqlDatabase:getExternalMySqlDatabase", args ?? new GetExternalMySqlDatabaseArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Retrieves the external MySQL database information.
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
        ///     var testExternalMySqlDatabase = Oci.DatabaseManagement.GetExternalMySqlDatabase.Invoke(new()
        ///     {
        ///         ExternalMySqlDatabaseId = testExternalMySqlDatabaseOciDatabaseManagementExternalMySqlDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalMySqlDatabaseResult> Invoke(GetExternalMySqlDatabaseInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalMySqlDatabaseResult>("oci:DatabaseManagement/getExternalMySqlDatabase:getExternalMySqlDatabase", args ?? new GetExternalMySqlDatabaseInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External My Sql Database resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Retrieves the external MySQL database information.
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
        ///     var testExternalMySqlDatabase = Oci.DatabaseManagement.GetExternalMySqlDatabase.Invoke(new()
        ///     {
        ///         ExternalMySqlDatabaseId = testExternalMySqlDatabaseOciDatabaseManagementExternalMySqlDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalMySqlDatabaseResult> Invoke(GetExternalMySqlDatabaseInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalMySqlDatabaseResult>("oci:DatabaseManagement/getExternalMySqlDatabase:getExternalMySqlDatabase", args ?? new GetExternalMySqlDatabaseInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalMySqlDatabaseArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the External MySQL Database.
        /// </summary>
        [Input("externalMySqlDatabaseId", required: true)]
        public string ExternalMySqlDatabaseId { get; set; } = null!;

        public GetExternalMySqlDatabaseArgs()
        {
        }
        public static new GetExternalMySqlDatabaseArgs Empty => new GetExternalMySqlDatabaseArgs();
    }

    public sealed class GetExternalMySqlDatabaseInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the External MySQL Database.
        /// </summary>
        [Input("externalMySqlDatabaseId", required: true)]
        public Input<string> ExternalMySqlDatabaseId { get; set; } = null!;

        public GetExternalMySqlDatabaseInvokeArgs()
        {
        }
        public static new GetExternalMySqlDatabaseInvokeArgs Empty => new GetExternalMySqlDatabaseInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalMySqlDatabaseResult
    {
        /// <summary>
        /// OCID of compartment for the External MySQL Database.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Display Name of the External MySQL Database.
        /// </summary>
        public readonly string DbName;
        /// <summary>
        /// OCID of External MySQL Database.
        /// </summary>
        public readonly string ExternalDatabaseId;
        public readonly string ExternalMySqlDatabaseId;
        public readonly string Id;

        [OutputConstructor]
        private GetExternalMySqlDatabaseResult(
            string compartmentId,

            string dbName,

            string externalDatabaseId,

            string externalMySqlDatabaseId,

            string id)
        {
            CompartmentId = compartmentId;
            DbName = dbName;
            ExternalDatabaseId = externalDatabaseId;
            ExternalMySqlDatabaseId = externalMySqlDatabaseId;
            Id = id;
        }
    }
}
