// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetAlerts
    {
        /// <summary>
        /// This data source provides the list of Alerts in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of all alerts.
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
        ///         var testAlerts = Output.Create(Oci.DataSafe.GetAlerts.InvokeAsync(new Oci.DataSafe.GetAlertsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Alert_access_level,
        ///             CompartmentIdInSubtree = @var.Alert_compartment_id_in_subtree,
        ///             Fields = @var.Alert_field,
        ///             Id = @var.Alert_id,
        ///             ScimQuery = @var.Alert_scim_query,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAlertsResult> InvokeAsync(GetAlertsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAlertsResult>("oci:DataSafe/getAlerts:getAlerts", args ?? new GetAlertsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Alerts in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of all alerts.
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
        ///         var testAlerts = Output.Create(Oci.DataSafe.GetAlerts.InvokeAsync(new Oci.DataSafe.GetAlertsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Alert_access_level,
        ///             CompartmentIdInSubtree = @var.Alert_compartment_id_in_subtree,
        ///             Fields = @var.Alert_field,
        ///             Id = @var.Alert_id,
        ///             ScimQuery = @var.Alert_scim_query,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAlertsResult> Invoke(GetAlertsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAlertsResult>("oci:DataSafe/getAlerts:getAlerts", args ?? new GetAlertsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAlertsArgs : Pulumi.InvokeArgs
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

        [Input("fields")]
        private List<string>? _fields;

        /// <summary>
        /// Specifies a subset of fields to be returned in the response.
        /// </summary>
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private List<Inputs.GetAlertsFilterArgs>? _filters;
        public List<Inputs.GetAlertsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAlertsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return alert by it's OCID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// </summary>
        [Input("scimQuery")]
        public string? ScimQuery { get; set; }

        public GetAlertsArgs()
        {
        }
    }

    public sealed class GetAlertsInvokeArgs : Pulumi.InvokeArgs
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

        [Input("fields")]
        private InputList<string>? _fields;

        /// <summary>
        /// Specifies a subset of fields to be returned in the response.
        /// </summary>
        public InputList<string> Fields
        {
            get => _fields ?? (_fields = new InputList<string>());
            set => _fields = value;
        }

        [Input("filters")]
        private InputList<Inputs.GetAlertsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAlertsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAlertsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return alert by it's OCID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// The scimQuery query parameter accepts filter expressions that use the syntax described in Section 3.2.2.2 of the System for Cross-Domain Identity Management (SCIM) specification, which is available at [RFC3339](https://tools.ietf.org/html/draft-ietf-scim-api-12). In SCIM filtering expressions, text, date, and time values must be enclosed in quotation marks, with date and time values using ISO-8601 format. (Numeric and boolean values should not be quoted.)
        /// </summary>
        [Input("scimQuery")]
        public Input<string>? ScimQuery { get; set; }

        public GetAlertsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAlertsResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The list of alert_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAlertsAlertCollectionResult> AlertCollections;
        /// <summary>
        /// The OCID of the compartment that contains the alert.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<string> Fields;
        public readonly ImmutableArray<Outputs.GetAlertsFilterResult> Filters;
        /// <summary>
        /// The OCID of the alert.
        /// </summary>
        public readonly string? Id;
        public readonly string? ScimQuery;

        [OutputConstructor]
        private GetAlertsResult(
            string? accessLevel,

            ImmutableArray<Outputs.GetAlertsAlertCollectionResult> alertCollections,

            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<string> fields,

            ImmutableArray<Outputs.GetAlertsFilterResult> filters,

            string? id,

            string? scimQuery)
        {
            AccessLevel = accessLevel;
            AlertCollections = alertCollections;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Fields = fields;
            Filters = filters;
            Id = id;
            ScimQuery = scimQuery;
        }
    }
}
