// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetAuditEvents
    {
        /// <summary>
        /// This data source provides the list of Audit Events in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// The ListAuditEvents operation returns specified `compartmentId` audit Events only.
        /// The list does not include any audit Events associated with the `subcompartments` of the specified `compartmentId`.
        /// 
        /// The parameter `accessLevel` specifies whether to return only those compartments for which the
        /// requestor has INSPECT permissions on at least one resource directly
        /// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
        /// Principal doesn't have access to even one of the child compartments. This is valid only when
        /// `compartmentIdInSubtree` is set to `true`.
        /// 
        /// The parameter `compartmentIdInSubtree` applies when you perform ListAuditEvents on the
        /// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
        /// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
        /// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
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
        ///     var testAuditEvents = Oci.DataSafe.GetAuditEvents.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         AccessLevel = @var.Audit_event_access_level,
        ///         CompartmentIdInSubtree = @var.Audit_event_compartment_id_in_subtree,
        ///         ScimQuery = @var.Audit_event_scim_query,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAuditEventsResult> InvokeAsync(GetAuditEventsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAuditEventsResult>("oci:DataSafe/getAuditEvents:getAuditEvents", args ?? new GetAuditEventsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Audit Events in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// The ListAuditEvents operation returns specified `compartmentId` audit Events only.
        /// The list does not include any audit Events associated with the `subcompartments` of the specified `compartmentId`.
        /// 
        /// The parameter `accessLevel` specifies whether to return only those compartments for which the
        /// requestor has INSPECT permissions on at least one resource directly
        /// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
        /// Principal doesn't have access to even one of the child compartments. This is valid only when
        /// `compartmentIdInSubtree` is set to `true`.
        /// 
        /// The parameter `compartmentIdInSubtree` applies when you perform ListAuditEvents on the
        /// `compartmentId` passed and when it is set to true, the entire hierarchy of compartments can be returned.
        /// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
        /// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
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
        ///     var testAuditEvents = Oci.DataSafe.GetAuditEvents.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         AccessLevel = @var.Audit_event_access_level,
        ///         CompartmentIdInSubtree = @var.Audit_event_compartment_id_in_subtree,
        ///         ScimQuery = @var.Audit_event_scim_query,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAuditEventsResult> Invoke(GetAuditEventsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAuditEventsResult>("oci:DataSafe/getAuditEvents:getAuditEvents", args ?? new GetAuditEventsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAuditEventsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetAuditEventsFilterArgs>? _filters;
        public List<Inputs.GetAuditEventsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAuditEventsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// </summary>
        [Input("scimQuery")]
        public string? ScimQuery { get; set; }

        public GetAuditEventsArgs()
        {
        }
        public static new GetAuditEventsArgs Empty => new GetAuditEventsArgs();
    }

    public sealed class GetAuditEventsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAuditEventsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAuditEventsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAuditEventsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// </summary>
        [Input("scimQuery")]
        public Input<string>? ScimQuery { get; set; }

        public GetAuditEventsInvokeArgs()
        {
        }
        public static new GetAuditEventsInvokeArgs Empty => new GetAuditEventsInvokeArgs();
    }


    [OutputType]
    public sealed class GetAuditEventsResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The list of audit_event_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAuditEventsAuditEventCollectionResult> AuditEventCollections;
        /// <summary>
        /// The OCID of the compartment containing the audit event. This is the same audited target database resource comparment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetAuditEventsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? ScimQuery;

        [OutputConstructor]
        private GetAuditEventsResult(
            string? accessLevel,

            ImmutableArray<Outputs.GetAuditEventsAuditEventCollectionResult> auditEventCollections,

            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetAuditEventsFilterResult> filters,

            string id,

            string? scimQuery)
        {
            AccessLevel = accessLevel;
            AuditEventCollections = auditEventCollections;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            ScimQuery = scimQuery;
        }
    }
}