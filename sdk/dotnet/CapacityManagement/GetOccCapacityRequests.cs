// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement
{
    public static class GetOccCapacityRequests
    {
        /// <summary>
        /// This data source provides the list of Occ Capacity Requests in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists all capacity requests.
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
        ///     var testOccCapacityRequests = Oci.CapacityManagement.GetOccCapacityRequests.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = occCapacityRequestDisplayName,
        ///         Id = occCapacityRequestId,
        ///         Namespace = occCapacityRequestNamespace,
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///         RequestType = occCapacityRequestRequestType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOccCapacityRequestsResult> InvokeAsync(GetOccCapacityRequestsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOccCapacityRequestsResult>("oci:CapacityManagement/getOccCapacityRequests:getOccCapacityRequests", args ?? new GetOccCapacityRequestsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Occ Capacity Requests in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists all capacity requests.
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
        ///     var testOccCapacityRequests = Oci.CapacityManagement.GetOccCapacityRequests.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = occCapacityRequestDisplayName,
        ///         Id = occCapacityRequestId,
        ///         Namespace = occCapacityRequestNamespace,
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///         RequestType = occCapacityRequestRequestType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccCapacityRequestsResult> Invoke(GetOccCapacityRequestsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccCapacityRequestsResult>("oci:CapacityManagement/getOccCapacityRequests:getOccCapacityRequests", args ?? new GetOccCapacityRequestsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Occ Capacity Requests in Oracle Cloud Infrastructure Capacity Management service.
        /// 
        /// Lists all capacity requests.
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
        ///     var testOccCapacityRequests = Oci.CapacityManagement.GetOccCapacityRequests.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = occCapacityRequestDisplayName,
        ///         Id = occCapacityRequestId,
        ///         Namespace = occCapacityRequestNamespace,
        ///         OccAvailabilityCatalogId = testOccAvailabilityCatalog.Id,
        ///         RequestType = occCapacityRequestRequestType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccCapacityRequestsResult> Invoke(GetOccCapacityRequestsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccCapacityRequestsResult>("oci:CapacityManagement/getOccCapacityRequests:getOccCapacityRequests", args ?? new GetOccCapacityRequestsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOccCapacityRequestsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the entire display name. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetOccCapacityRequestsFilterArgs>? _filters;
        public List<Inputs.GetOccCapacityRequestsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOccCapacityRequestsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the capacity request. This is done for the users who have INSPECT permission on the resource but do not have READ permission.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The namespace by which we would filter the list.
        /// </summary>
        [Input("namespace")]
        public string? Namespace { get; set; }

        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the availability catalog against which they were created.
        /// </summary>
        [Input("occAvailabilityCatalogId")]
        public string? OccAvailabilityCatalogId { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the request type. The match is not case sensitive.
        /// </summary>
        [Input("requestType")]
        public string? RequestType { get; set; }

        public GetOccCapacityRequestsArgs()
        {
        }
        public static new GetOccCapacityRequestsArgs Empty => new GetOccCapacityRequestsArgs();
    }

    public sealed class GetOccCapacityRequestsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only the resources that match the entire display name. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOccCapacityRequestsFilterInputArgs>? _filters;
        public InputList<Inputs.GetOccCapacityRequestsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOccCapacityRequestsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the capacity request. This is done for the users who have INSPECT permission on the resource but do not have READ permission.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The namespace by which we would filter the list.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        /// <summary>
        /// A filter to return the list of capacity requests based on the OCID of the availability catalog against which they were created.
        /// </summary>
        [Input("occAvailabilityCatalogId")]
        public Input<string>? OccAvailabilityCatalogId { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the request type. The match is not case sensitive.
        /// </summary>
        [Input("requestType")]
        public Input<string>? RequestType { get; set; }

        public GetOccCapacityRequestsInvokeArgs()
        {
        }
        public static new GetOccCapacityRequestsInvokeArgs Empty => new GetOccCapacityRequestsInvokeArgs();
    }


    [OutputType]
    public sealed class GetOccCapacityRequestsResult
    {
        /// <summary>
        /// The OCID of the tenancy from which the request was made.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The display name of the capacity request.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOccCapacityRequestsFilterResult> Filters;
        /// <summary>
        /// The OCID of the capacity request.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The name of the Oracle Cloud Infrastructure service in consideration. For example, Compute, Exadata, and so on.
        /// </summary>
        public readonly string? Namespace;
        /// <summary>
        /// The OCID of the availability catalog against which the capacity request was placed.
        /// </summary>
        public readonly string? OccAvailabilityCatalogId;
        /// <summary>
        /// The list of occ_capacity_request_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionResult> OccCapacityRequestCollections;
        /// <summary>
        /// Type of Capacity Request(New or Transfer)
        /// </summary>
        public readonly string? RequestType;

        [OutputConstructor]
        private GetOccCapacityRequestsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetOccCapacityRequestsFilterResult> filters,

            string? id,

            string? @namespace,

            string? occAvailabilityCatalogId,

            ImmutableArray<Outputs.GetOccCapacityRequestsOccCapacityRequestCollectionResult> occCapacityRequestCollections,

            string? requestType)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Namespace = @namespace;
            OccAvailabilityCatalogId = occAvailabilityCatalogId;
            OccCapacityRequestCollections = occCapacityRequestCollections;
            RequestType = requestType;
        }
    }
}
