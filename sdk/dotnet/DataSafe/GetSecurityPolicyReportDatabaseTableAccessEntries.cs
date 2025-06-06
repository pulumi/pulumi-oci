// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetSecurityPolicyReportDatabaseTableAccessEntries
    {
        /// <summary>
        /// This data source provides the list of Security Policy Report Database Table Access Entries in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all database table access entries in Data Safe.
        ///   
        /// The ListDatabaseTableAccessEntries operation returns only the database table access reports for the specified security policy report.
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
        ///     var testSecurityPolicyReportDatabaseTableAccessEntries = Oci.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntries.Invoke(new()
        ///     {
        ///         SecurityPolicyReportId = testSecurityPolicyReport.Id,
        ///         ScimQuery = securityPolicyReportDatabaseTableAccessEntryScimQuery,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSecurityPolicyReportDatabaseTableAccessEntriesResult> InvokeAsync(GetSecurityPolicyReportDatabaseTableAccessEntriesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSecurityPolicyReportDatabaseTableAccessEntriesResult>("oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntries:getSecurityPolicyReportDatabaseTableAccessEntries", args ?? new GetSecurityPolicyReportDatabaseTableAccessEntriesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Policy Report Database Table Access Entries in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all database table access entries in Data Safe.
        ///   
        /// The ListDatabaseTableAccessEntries operation returns only the database table access reports for the specified security policy report.
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
        ///     var testSecurityPolicyReportDatabaseTableAccessEntries = Oci.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntries.Invoke(new()
        ///     {
        ///         SecurityPolicyReportId = testSecurityPolicyReport.Id,
        ///         ScimQuery = securityPolicyReportDatabaseTableAccessEntryScimQuery,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityPolicyReportDatabaseTableAccessEntriesResult> Invoke(GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityPolicyReportDatabaseTableAccessEntriesResult>("oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntries:getSecurityPolicyReportDatabaseTableAccessEntries", args ?? new GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Policy Report Database Table Access Entries in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all database table access entries in Data Safe.
        ///   
        /// The ListDatabaseTableAccessEntries operation returns only the database table access reports for the specified security policy report.
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
        ///     var testSecurityPolicyReportDatabaseTableAccessEntries = Oci.DataSafe.GetSecurityPolicyReportDatabaseTableAccessEntries.Invoke(new()
        ///     {
        ///         SecurityPolicyReportId = testSecurityPolicyReport.Id,
        ///         ScimQuery = securityPolicyReportDatabaseTableAccessEntryScimQuery,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityPolicyReportDatabaseTableAccessEntriesResult> Invoke(GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityPolicyReportDatabaseTableAccessEntriesResult>("oci:DataSafe/getSecurityPolicyReportDatabaseTableAccessEntries:getSecurityPolicyReportDatabaseTableAccessEntries", args ?? new GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSecurityPolicyReportDatabaseTableAccessEntriesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterArgs>? _filters;
        public List<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// 
        /// **Example:** query=(accessType eq 'SELECT') and (grantee eq 'ADMIN')
        /// </summary>
        [Input("scimQuery")]
        public string? ScimQuery { get; set; }

        /// <summary>
        /// The OCID of the security policy report resource.
        /// </summary>
        [Input("securityPolicyReportId", required: true)]
        public string SecurityPolicyReportId { get; set; } = null!;

        public GetSecurityPolicyReportDatabaseTableAccessEntriesArgs()
        {
        }
        public static new GetSecurityPolicyReportDatabaseTableAccessEntriesArgs Empty => new GetSecurityPolicyReportDatabaseTableAccessEntriesArgs();
    }

    public sealed class GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// 
        /// **Example:** query=(accessType eq 'SELECT') and (grantee eq 'ADMIN')
        /// </summary>
        [Input("scimQuery")]
        public Input<string>? ScimQuery { get; set; }

        /// <summary>
        /// The OCID of the security policy report resource.
        /// </summary>
        [Input("securityPolicyReportId", required: true)]
        public Input<string> SecurityPolicyReportId { get; set; } = null!;

        public GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs()
        {
        }
        public static new GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs Empty => new GetSecurityPolicyReportDatabaseTableAccessEntriesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSecurityPolicyReportDatabaseTableAccessEntriesResult
    {
        /// <summary>
        /// The list of database_table_access_entry_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityPolicyReportDatabaseTableAccessEntriesDatabaseTableAccessEntryCollectionResult> DatabaseTableAccessEntryCollections;
        public readonly ImmutableArray<Outputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? ScimQuery;
        public readonly string SecurityPolicyReportId;

        [OutputConstructor]
        private GetSecurityPolicyReportDatabaseTableAccessEntriesResult(
            ImmutableArray<Outputs.GetSecurityPolicyReportDatabaseTableAccessEntriesDatabaseTableAccessEntryCollectionResult> databaseTableAccessEntryCollections,

            ImmutableArray<Outputs.GetSecurityPolicyReportDatabaseTableAccessEntriesFilterResult> filters,

            string id,

            string? scimQuery,

            string securityPolicyReportId)
        {
            DatabaseTableAccessEntryCollections = databaseTableAccessEntryCollections;
            Filters = filters;
            Id = id;
            ScimQuery = scimQuery;
            SecurityPolicyReportId = securityPolicyReportId;
        }
    }
}
