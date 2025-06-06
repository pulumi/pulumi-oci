// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsMyCompletedApproval
    {
        /// <summary>
        /// This data source provides details about a specific My Completed Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyCompletedApproval
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
        ///     var testMyCompletedApproval = Oci.Identity.GetDomainsMyCompletedApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyCompletedApprovalId = testMyCompletedApprovalOciIdentityDomainsMyCompletedApproval.Id,
        ///         Authorization = myCompletedApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myCompletedApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDomainsMyCompletedApprovalResult> InvokeAsync(GetDomainsMyCompletedApprovalArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsMyCompletedApprovalResult>("oci:Identity/getDomainsMyCompletedApproval:getDomainsMyCompletedApproval", args ?? new GetDomainsMyCompletedApprovalArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific My Completed Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyCompletedApproval
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
        ///     var testMyCompletedApproval = Oci.Identity.GetDomainsMyCompletedApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyCompletedApprovalId = testMyCompletedApprovalOciIdentityDomainsMyCompletedApproval.Id,
        ///         Authorization = myCompletedApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myCompletedApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsMyCompletedApprovalResult> Invoke(GetDomainsMyCompletedApprovalInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsMyCompletedApprovalResult>("oci:Identity/getDomainsMyCompletedApproval:getDomainsMyCompletedApproval", args ?? new GetDomainsMyCompletedApprovalInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific My Completed Approval resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get My MyCompletedApproval
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
        ///     var testMyCompletedApproval = Oci.Identity.GetDomainsMyCompletedApproval.Invoke(new()
        ///     {
        ///         IdcsEndpoint = testDomain.Url,
        ///         MyCompletedApprovalId = testMyCompletedApprovalOciIdentityDomainsMyCompletedApproval.Id,
        ///         Authorization = myCompletedApprovalAuthorization,
        ///         ResourceTypeSchemaVersion = myCompletedApprovalResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsMyCompletedApprovalResult> Invoke(GetDomainsMyCompletedApprovalInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsMyCompletedApprovalResult>("oci:Identity/getDomainsMyCompletedApproval:getDomainsMyCompletedApproval", args ?? new GetDomainsMyCompletedApprovalInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsMyCompletedApprovalArgs : global::Pulumi.InvokeArgs
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
        [Input("myCompletedApprovalId", required: true)]
        public string MyCompletedApprovalId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsMyCompletedApprovalArgs()
        {
        }
        public static new GetDomainsMyCompletedApprovalArgs Empty => new GetDomainsMyCompletedApprovalArgs();
    }

    public sealed class GetDomainsMyCompletedApprovalInvokeArgs : global::Pulumi.InvokeArgs
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
        [Input("myCompletedApprovalId", required: true)]
        public Input<string> MyCompletedApprovalId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsMyCompletedApprovalInvokeArgs()
        {
        }
        public static new GetDomainsMyCompletedApprovalInvokeArgs Empty => new GetDomainsMyCompletedApprovalInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsMyCompletedApprovalResult
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
        public readonly ImmutableArray<Outputs.GetDomainsMyCompletedApprovalIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsMyCompletedApprovalIdcsLastModifiedByResult> IdcsLastModifiedBies;
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
        public readonly ImmutableArray<Outputs.GetDomainsMyCompletedApprovalMetaResult> Metas;
        public readonly string MyCompletedApprovalId;
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
        public readonly ImmutableArray<Outputs.GetDomainsMyCompletedApprovalTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;

        [OutputConstructor]
        private GetDomainsMyCompletedApprovalResult(
            string? authorization,

            string compartmentOcid,

            bool deleteInProgress,

            string domainOcid,

            string expires,

            string id,

            ImmutableArray<Outputs.GetDomainsMyCompletedApprovalIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsMyCompletedApprovalIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            string justification,

            ImmutableArray<Outputs.GetDomainsMyCompletedApprovalMetaResult> metas,

            string myCompletedApprovalId,

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

            ImmutableArray<Outputs.GetDomainsMyCompletedApprovalTagResult> tags,

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
            MyCompletedApprovalId = myCompletedApprovalId;
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
