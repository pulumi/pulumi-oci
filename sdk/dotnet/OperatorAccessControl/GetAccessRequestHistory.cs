// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OperatorAccessControl
{
    public static class GetAccessRequestHistory
    {
        /// <summary>
        /// This data source provides details about a specific Access Request History resource in Oracle Cloud Infrastructure Operator Access Control service.
        /// 
        /// Returns a history of all status associated with the accessRequestId.
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
        ///         var testAccessRequestHistory = Output.Create(Oci.OperatorAccessControl.GetAccessRequestHistory.InvokeAsync(new Oci.OperatorAccessControl.GetAccessRequestHistoryArgs
        ///         {
        ///             AccessRequestId = oci_operator_access_control_access_request.Test_access_request.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAccessRequestHistoryResult> InvokeAsync(GetAccessRequestHistoryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAccessRequestHistoryResult>("oci:OperatorAccessControl/getAccessRequestHistory:getAccessRequestHistory", args ?? new GetAccessRequestHistoryArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Access Request History resource in Oracle Cloud Infrastructure Operator Access Control service.
        /// 
        /// Returns a history of all status associated with the accessRequestId.
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
        ///         var testAccessRequestHistory = Output.Create(Oci.OperatorAccessControl.GetAccessRequestHistory.InvokeAsync(new Oci.OperatorAccessControl.GetAccessRequestHistoryArgs
        ///         {
        ///             AccessRequestId = oci_operator_access_control_access_request.Test_access_request.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAccessRequestHistoryResult> Invoke(GetAccessRequestHistoryInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAccessRequestHistoryResult>("oci:OperatorAccessControl/getAccessRequestHistory:getAccessRequestHistory", args ?? new GetAccessRequestHistoryInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAccessRequestHistoryArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique AccessRequest identifier
        /// </summary>
        [Input("accessRequestId", required: true)]
        public string AccessRequestId { get; set; } = null!;

        public GetAccessRequestHistoryArgs()
        {
        }
    }

    public sealed class GetAccessRequestHistoryInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique AccessRequest identifier
        /// </summary>
        [Input("accessRequestId", required: true)]
        public Input<string> AccessRequestId { get; set; } = null!;

        public GetAccessRequestHistoryInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAccessRequestHistoryResult
    {
        public readonly string AccessRequestId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// contains AccessRequestHistorySummary
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAccessRequestHistoryItemResult> Items;

        [OutputConstructor]
        private GetAccessRequestHistoryResult(
            string accessRequestId,

            string id,

            ImmutableArray<Outputs.GetAccessRequestHistoryItemResult> items)
        {
            AccessRequestId = accessRequestId;
            Id = id;
            Items = items;
        }
    }
}
