// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetDiscoveryJobsResult
    {
        /// <summary>
        /// This data source provides details about a specific Discovery Jobs Result resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of the specified discovery result.
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
        ///     var testDiscoveryJobsResult = Oci.DataSafe.GetDiscoveryJobsResult.Invoke(new()
        ///     {
        ///         DiscoveryJobId = oci_data_safe_discovery_job.Test_discovery_job.Id,
        ///         ResultKey = @var.Discovery_jobs_result_result_key,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDiscoveryJobsResultResult> InvokeAsync(GetDiscoveryJobsResultArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDiscoveryJobsResultResult>("oci:DataSafe/getDiscoveryJobsResult:getDiscoveryJobsResult", args ?? new GetDiscoveryJobsResultArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Discovery Jobs Result resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of the specified discovery result.
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
        ///     var testDiscoveryJobsResult = Oci.DataSafe.GetDiscoveryJobsResult.Invoke(new()
        ///     {
        ///         DiscoveryJobId = oci_data_safe_discovery_job.Test_discovery_job.Id,
        ///         ResultKey = @var.Discovery_jobs_result_result_key,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDiscoveryJobsResultResult> Invoke(GetDiscoveryJobsResultInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDiscoveryJobsResultResult>("oci:DataSafe/getDiscoveryJobsResult:getDiscoveryJobsResult", args ?? new GetDiscoveryJobsResultInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDiscoveryJobsResultArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the discovery job.
        /// </summary>
        [Input("discoveryJobId", required: true)]
        public string DiscoveryJobId { get; set; } = null!;

        /// <summary>
        /// The unique key that identifies the discovery result.
        /// </summary>
        [Input("resultKey", required: true)]
        public string ResultKey { get; set; } = null!;

        public GetDiscoveryJobsResultArgs()
        {
        }
        public static new GetDiscoveryJobsResultArgs Empty => new GetDiscoveryJobsResultArgs();
    }

    public sealed class GetDiscoveryJobsResultInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the discovery job.
        /// </summary>
        [Input("discoveryJobId", required: true)]
        public Input<string> DiscoveryJobId { get; set; } = null!;

        /// <summary>
        /// The unique key that identifies the discovery result.
        /// </summary>
        [Input("resultKey", required: true)]
        public Input<string> ResultKey { get; set; } = null!;

        public GetDiscoveryJobsResultInvokeArgs()
        {
        }
        public static new GetDiscoveryJobsResultInvokeArgs Empty => new GetDiscoveryJobsResultInvokeArgs();
    }


    [OutputType]
    public sealed class GetDiscoveryJobsResultResult
    {
        /// <summary>
        /// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> AppDefinedChildColumnKeys;
        /// <summary>
        /// The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
        /// </summary>
        public readonly string AppName;
        /// <summary>
        /// The name of the sensitive column.
        /// </summary>
        public readonly string ColumnName;
        /// <summary>
        /// The data type of the sensitive column.
        /// </summary>
        public readonly string DataType;
        /// <summary>
        /// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> DbDefinedChildColumnKeys;
        public readonly string DiscoveryJobId;
        /// <summary>
        /// The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
        /// </summary>
        public readonly string DiscoveryType;
        /// <summary>
        /// The estimated number of data values the column has in the associated database.
        /// </summary>
        public readonly string EstimatedDataValueCount;
        public readonly string Id;
        /// <summary>
        /// Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
        /// </summary>
        public readonly bool IsResultApplied;
        /// <summary>
        /// The unique key that identifies the discovery result.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The attributes of a sensitive column that have been modified in the target database. It's populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDiscoveryJobsResultModifiedAttributeResult> ModifiedAttributes;
        /// <summary>
        /// The database object that contains the sensitive column.
        /// </summary>
        public readonly string Object;
        /// <summary>
        /// The type of the database object that contains the sensitive column.
        /// </summary>
        public readonly string ObjectType;
        /// <summary>
        /// Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
        /// </summary>
        public readonly ImmutableArray<string> ParentColumnKeys;
        /// <summary>
        /// Specifies how to process the discovery result. It's set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn't change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren't reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
        /// </summary>
        public readonly string PlannedAction;
        /// <summary>
        /// The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
        /// </summary>
        public readonly string RelationType;
        public readonly string ResultKey;
        /// <summary>
        /// Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> SampleDataValues;
        /// <summary>
        /// The database schema that contains the sensitive column.
        /// </summary>
        public readonly string SchemaName;
        /// <summary>
        /// The unique key that identifies the sensitive column represented by the discovery result.
        /// </summary>
        public readonly string SensitiveColumnkey;
        /// <summary>
        /// The OCID of the sensitive type associated with the sensitive column.
        /// </summary>
        public readonly string SensitiveTypeId;

        [OutputConstructor]
        private GetDiscoveryJobsResultResult(
            ImmutableArray<string> appDefinedChildColumnKeys,

            string appName,

            string columnName,

            string dataType,

            ImmutableArray<string> dbDefinedChildColumnKeys,

            string discoveryJobId,

            string discoveryType,

            string estimatedDataValueCount,

            string id,

            bool isResultApplied,

            string key,

            ImmutableArray<Outputs.GetDiscoveryJobsResultModifiedAttributeResult> modifiedAttributes,

            string @object,

            string objectType,

            ImmutableArray<string> parentColumnKeys,

            string plannedAction,

            string relationType,

            string resultKey,

            ImmutableArray<string> sampleDataValues,

            string schemaName,

            string sensitiveColumnkey,

            string sensitiveTypeId)
        {
            AppDefinedChildColumnKeys = appDefinedChildColumnKeys;
            AppName = appName;
            ColumnName = columnName;
            DataType = dataType;
            DbDefinedChildColumnKeys = dbDefinedChildColumnKeys;
            DiscoveryJobId = discoveryJobId;
            DiscoveryType = discoveryType;
            EstimatedDataValueCount = estimatedDataValueCount;
            Id = id;
            IsResultApplied = isResultApplied;
            Key = key;
            ModifiedAttributes = modifiedAttributes;
            Object = @object;
            ObjectType = objectType;
            ParentColumnKeys = parentColumnKeys;
            PlannedAction = plannedAction;
            RelationType = relationType;
            ResultKey = resultKey;
            SampleDataValues = sampleDataValues;
            SchemaName = schemaName;
            SensitiveColumnkey = sensitiveColumnkey;
            SensitiveTypeId = sensitiveTypeId;
        }
    }
}