// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetAuditArchiveRetrieval
    {
        /// <summary>
        /// This data source provides details about a specific Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of the specified archive retreival.
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
        ///     var testAuditArchiveRetrieval = Oci.DataSafe.GetAuditArchiveRetrieval.Invoke(new()
        ///     {
        ///         AuditArchiveRetrievalId = oci_data_safe_audit_archive_retrieval.Test_audit_archive_retrieval.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAuditArchiveRetrievalResult> InvokeAsync(GetAuditArchiveRetrievalArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAuditArchiveRetrievalResult>("oci:DataSafe/getAuditArchiveRetrieval:getAuditArchiveRetrieval", args ?? new GetAuditArchiveRetrievalArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets the details of the specified archive retreival.
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
        ///     var testAuditArchiveRetrieval = Oci.DataSafe.GetAuditArchiveRetrieval.Invoke(new()
        ///     {
        ///         AuditArchiveRetrievalId = oci_data_safe_audit_archive_retrieval.Test_audit_archive_retrieval.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAuditArchiveRetrievalResult> Invoke(GetAuditArchiveRetrievalInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAuditArchiveRetrievalResult>("oci:DataSafe/getAuditArchiveRetrieval:getAuditArchiveRetrieval", args ?? new GetAuditArchiveRetrievalInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAuditArchiveRetrievalArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of the archive retrieval.
        /// </summary>
        [Input("auditArchiveRetrievalId", required: true)]
        public string AuditArchiveRetrievalId { get; set; } = null!;

        public GetAuditArchiveRetrievalArgs()
        {
        }
        public static new GetAuditArchiveRetrievalArgs Empty => new GetAuditArchiveRetrievalArgs();
    }

    public sealed class GetAuditArchiveRetrievalInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of the archive retrieval.
        /// </summary>
        [Input("auditArchiveRetrievalId", required: true)]
        public Input<string> AuditArchiveRetrievalId { get; set; } = null!;

        public GetAuditArchiveRetrievalInvokeArgs()
        {
        }
        public static new GetAuditArchiveRetrievalInvokeArgs Empty => new GetAuditArchiveRetrievalInvokeArgs();
    }


    [OutputType]
    public sealed class GetAuditArchiveRetrievalResult
    {
        public readonly string AuditArchiveRetrievalId;
        /// <summary>
        /// Total count of audit events to be retrieved from the archive for the specified date range.
        /// </summary>
        public readonly string AuditEventCount;
        /// <summary>
        /// The OCID of the compartment that contains archive retrieval.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Description of the archive retrieval.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The display name of the archive retrieval. The name does not have to be unique, and is changeable.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// End month of the archive retrieval, in the format defined by RFC3339.
        /// </summary>
        public readonly string EndDate;
        /// <summary>
        /// The Error details of a failed archive retrieval.
        /// </summary>
        public readonly string ErrorInfo;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the archive retrieval.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details about the current state of the archive retrieval.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Start month of the archive retrieval, in the format defined by RFC3339.
        /// </summary>
        public readonly string StartDate;
        /// <summary>
        /// The current state of the archive retrieval.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The OCID of the target associated with the archive retrieval.
        /// </summary>
        public readonly string TargetId;
        /// <summary>
        /// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCompleted;
        /// <summary>
        /// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
        /// </summary>
        public readonly string TimeOfExpiry;
        /// <summary>
        /// The date time when archive retrieval was requested, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeRequested;

        [OutputConstructor]
        private GetAuditArchiveRetrievalResult(
            string auditArchiveRetrievalId,

            string auditEventCount,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string endDate,

            string errorInfo,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string startDate,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string targetId,

            string timeCompleted,

            string timeOfExpiry,

            string timeRequested)
        {
            AuditArchiveRetrievalId = auditArchiveRetrievalId;
            AuditEventCount = auditEventCount;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            EndDate = endDate;
            ErrorInfo = errorInfo;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            StartDate = startDate;
            State = state;
            SystemTags = systemTags;
            TargetId = targetId;
            TimeCompleted = timeCompleted;
            TimeOfExpiry = timeOfExpiry;
            TimeRequested = timeRequested;
        }
    }
}