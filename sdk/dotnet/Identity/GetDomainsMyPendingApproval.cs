// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsMyPendingApproval
    {
        /// <summary>
        /// This data source provides details about a specific My Pending Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyPendingApproval
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
        ///     var testMyPendingApproval = Oci.Identity.GetDomainsMyPendingApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyPendingApprovalId = testMyPendingApprovalOciIdentityDomainsMyPendingApproval.Id,
        ///         Authorization = myPendingApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myPendingApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDomainsMyPendingApprovalResult> InvokeAsync(GetDomainsMyPendingApprovalArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsMyPendingApprovalResult>("oci:Identity/getDomainsMyPendingApproval:getDomainsMyPendingApproval", args ?? new GetDomainsMyPendingApprovalArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific My Pending Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyPendingApproval
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
        ///     var testMyPendingApproval = Oci.Identity.GetDomainsMyPendingApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyPendingApprovalId = testMyPendingApprovalOciIdentityDomainsMyPendingApproval.Id,
        ///         Authorization = myPendingApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myPendingApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsMyPendingApprovalResult> Invoke(GetDomainsMyPendingApprovalInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsMyPendingApprovalResult>("oci:Identity/getDomainsMyPendingApproval:getDomainsMyPendingApproval", args ?? new GetDomainsMyPendingApprovalInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific My Pending Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyPendingApproval
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
        ///     var testMyPendingApproval = Oci.Identity.GetDomainsMyPendingApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyPendingApprovalId = testMyPendingApprovalOciIdentityDomainsMyPendingApproval.Id,
        ///         Authorization = myPendingApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myPendingApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsMyPendingApprovalResult> Invoke(GetDomainsMyPendingApprovalInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsMyPendingApprovalResult>("oci:Identity/getDomainsMyPendingApproval:getDomainsMyPendingApproval", args ?? new GetDomainsMyPendingApprovalInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsMyPendingApprovalArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public string? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public string IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("myPendingApprovalId", required: true)]
        public string MyPendingApprovalId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsMyPendingApprovalArgs()
        {
        }
        public static new GetDomainsMyPendingApprovalArgs Empty => new GetDomainsMyPendingApprovalArgs();
    }

    public sealed class GetDomainsMyPendingApprovalInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public Input<string>? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("myPendingApprovalId", required: true)]
        public Input<string> MyPendingApprovalId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsMyPendingApprovalInvokeArgs()
        {
        }
        public static new GetDomainsMyPendingApprovalInvokeArgs Empty => new GetDomainsMyPendingApprovalInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsMyPendingApprovalResult
    {
        public readonly string? Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// Time by when ApprovalWorkflowInstance expires
        /// </summary>
        public readonly string Expires;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyPendingApprovalIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyPendingApprovalIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Justification for approval
        /// </summary>
        public readonly string Justification;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyPendingApprovalMetaResult> Metas;
        public readonly string MyPendingApprovalId;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// The time that the Request was created
        /// </summary>
        public readonly string RequestCreatedTime;
        /// <summary>
        /// Request Details
        /// </summary>
        public readonly string RequestDetails;
        /// <summary>
        /// The Unique Identifier of the request.
        /// </summary>
        public readonly string RequestId;
        /// <summary>
        /// The Oracle Cloud Infrastructure Unique Identifier of the request.
        /// </summary>
        public readonly string RequestOcid;
        /// <summary>
        /// Requested Resource display name
        /// </summary>
        public readonly string ResourceDisplayName;
        /// <summary>
        /// Requested Resource type
        /// </summary>
        public readonly string ResourceType;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// The time that the user responded to the Approval
        /// </summary>
        public readonly string ResponseTime;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// Status of the approver's response on the approval
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyPendingApprovalTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;

        [OutputConstructor]
        private GetDomainsMyPendingApprovalResult(
            string? authorization,

            string compartmentOcid,

            bool deleteInProgress,

            string domainOcid,

            string expires,

            string id,

            ImmutableArray<Outputs.GetDomainsMyPendingApprovalIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsMyPendingApprovalIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            string justification,

            ImmutableArray<Outputs.GetDomainsMyPendingApprovalMetaResult> metas,

            string myPendingApprovalId,

            string ocid,

            string requestCreatedTime,

            string requestDetails,

            string requestId,

            string requestOcid,

            string resourceDisplayName,

            string resourceType,

            string? resourceTypeSchemaVersion,

            string responseTime,

            ImmutableArray<string> schemas,

            string status,

            ImmutableArray<Outputs.GetDomainsMyPendingApprovalTagResult> tags,

            string tenancyOcid)
        {
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            DeleteInProgress = deleteInProgress;
            DomainOcid = domainOcid;
            Expires = expires;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            Justification = justification;
            Metas = metas;
            MyPendingApprovalId = myPendingApprovalId;
            Ocid = ocid;
            RequestCreatedTime = requestCreatedTime;
            RequestDetails = requestDetails;
            RequestId = requestId;
            RequestOcid = requestOcid;
            ResourceDisplayName = resourceDisplayName;
            ResourceType = resourceType;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            ResponseTime = responseTime;
            Schemas = schemas;
            Status = status;
            Tags = tags;
            TenancyOcid = tenancyOcid;
        }
    }
}
