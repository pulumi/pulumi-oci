// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetZones
    {
        /// <summary>
        /// This data source provides the list of Zones in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all zones in the specified compartment. The collection
        /// can be filtered by name, time created, scope, associated view, and zone type.
        /// Additionally, for Private DNS, the `scope` query parameter is required when 
        /// listing private zones.
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
        ///     var testZones = Oci.Dns.GetZones.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         Name = @var.Zone_name,
        ///         NameContains = @var.Zone_name_contains,
        ///         Scope = @var.Zone_scope,
        ///         State = @var.Zone_state,
        ///         TimeCreatedGreaterThanOrEqualTo = @var.Zone_time_created_greater_than_or_equal_to,
        ///         TimeCreatedLessThan = @var.Zone_time_created_less_than,
        ///         TsigKeyId = oci_dns_tsig_key.Test_tsig_key.Id,
        ///         ViewId = oci_dns_view.Test_view.Id,
        ///         ZoneType = @var.Zone_zone_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetZonesResult> InvokeAsync(GetZonesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetZonesResult>("oci:Dns/getZones:getZones", args ?? new GetZonesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Zones in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets a list of all zones in the specified compartment. The collection
        /// can be filtered by name, time created, scope, associated view, and zone type.
        /// Additionally, for Private DNS, the `scope` query parameter is required when 
        /// listing private zones.
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
        ///     var testZones = Oci.Dns.GetZones.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         Name = @var.Zone_name,
        ///         NameContains = @var.Zone_name_contains,
        ///         Scope = @var.Zone_scope,
        ///         State = @var.Zone_state,
        ///         TimeCreatedGreaterThanOrEqualTo = @var.Zone_time_created_greater_than_or_equal_to,
        ///         TimeCreatedLessThan = @var.Zone_time_created_less_than,
        ///         TsigKeyId = oci_dns_tsig_key.Test_tsig_key.Id,
        ///         ViewId = oci_dns_view.Test_view.Id,
        ///         ZoneType = @var.Zone_zone_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetZonesResult> Invoke(GetZonesInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetZonesResult>("oci:Dns/getZones:getZones", args ?? new GetZonesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetZonesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetZonesFilterArgs>? _filters;
        public List<Inputs.GetZonesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetZonesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A case-sensitive filter for zone names. Will match any zone with a name that equals the provided value.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// Search by zone name. Will match any zone whose name (case-insensitive) contains the provided value.
        /// </summary>
        [Input("nameContains")]
        public string? NameContains { get; set; }

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope. This value will be null 
        /// for zones in the global DNS and `PRIVATE` when listing private zones.
        /// </summary>
        [Input("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// The field by which to sort zones. Allowed values are: name|zoneType|timeCreated
        /// </summary>
        [Input("sortBy")]
        public string? SortBy { get; set; }

        /// <summary>
        /// The order to sort the resources. Allowed values are: ASC|DESC
        /// </summary>
        [Input("sortOrder")]
        public string? SortOrder { get; set; }

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created on or after the indicated time.
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public string? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created before the indicated time.
        /// </summary>
        [Input("timeCreatedLessThan")]
        public string? TimeCreatedLessThan { get; set; }

        /// <summary>
        /// Search for zones that are associated with a TSIG key.
        /// </summary>
        [Input("tsigKeyId")]
        public string? TsigKeyId { get; set; }

        /// <summary>
        /// The OCID of the view the resource is associated with.
        /// </summary>
        [Input("viewId")]
        public string? ViewId { get; set; }

        /// <summary>
        /// Search by zone type, `PRIMARY` or `SECONDARY`. Will match any zone whose type equals the provided value.
        /// </summary>
        [Input("zoneType")]
        public string? ZoneType { get; set; }

        public GetZonesArgs()
        {
        }
        public static new GetZonesArgs Empty => new GetZonesArgs();
    }

    public sealed class GetZonesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetZonesFilterInputArgs>? _filters;
        public InputList<Inputs.GetZonesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetZonesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A case-sensitive filter for zone names. Will match any zone with a name that equals the provided value.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Search by zone name. Will match any zone whose name (case-insensitive) contains the provided value.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        /// <summary>
        /// Specifies to operate only on resources that have a matching DNS scope. This value will be null 
        /// for zones in the global DNS and `PRIVATE` when listing private zones.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The field by which to sort zones. Allowed values are: name|zoneType|timeCreated
        /// </summary>
        [Input("sortBy")]
        public Input<string>? SortBy { get; set; }

        /// <summary>
        /// The order to sort the resources. Allowed values are: ASC|DESC
        /// </summary>
        [Input("sortOrder")]
        public Input<string>? SortOrder { get; set; }

        /// <summary>
        /// The state of a resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created on or after the indicated time.
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public Input<string>? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// An [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) timestamp that states all returned resources were created before the indicated time.
        /// </summary>
        [Input("timeCreatedLessThan")]
        public Input<string>? TimeCreatedLessThan { get; set; }

        /// <summary>
        /// Search for zones that are associated with a TSIG key.
        /// </summary>
        [Input("tsigKeyId")]
        public Input<string>? TsigKeyId { get; set; }

        /// <summary>
        /// The OCID of the view the resource is associated with.
        /// </summary>
        [Input("viewId")]
        public Input<string>? ViewId { get; set; }

        /// <summary>
        /// Search by zone type, `PRIMARY` or `SECONDARY`. Will match any zone whose type equals the provided value.
        /// </summary>
        [Input("zoneType")]
        public Input<string>? ZoneType { get; set; }

        public GetZonesInvokeArgs()
        {
        }
        public static new GetZonesInvokeArgs Empty => new GetZonesInvokeArgs();
    }


    [OutputType]
    public sealed class GetZonesResult
    {
        /// <summary>
        /// The OCID of the compartment containing the zone.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetZonesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The name of the zone.
        /// </summary>
        public readonly string? Name;
        public readonly string? NameContains;
        /// <summary>
        /// The scope of the zone.
        /// </summary>
        public readonly string? Scope;
        public readonly string? SortBy;
        public readonly string? SortOrder;
        /// <summary>
        /// The current state of the zone resource.
        /// </summary>
        public readonly string? State;
        public readonly string? TimeCreatedGreaterThanOrEqualTo;
        public readonly string? TimeCreatedLessThan;
        /// <summary>
        /// The OCID of the TSIG key.
        /// </summary>
        public readonly string? TsigKeyId;
        /// <summary>
        /// The OCID of the private view containing the zone. This value will be null for zones in the global DNS, which are publicly resolvable and not part of a private view.
        /// </summary>
        public readonly string? ViewId;
        /// <summary>
        /// The type of the zone. Must be either `PRIMARY` or `SECONDARY`. `SECONDARY` is only supported for GLOBAL zones.
        /// </summary>
        public readonly string? ZoneType;
        /// <summary>
        /// The list of zones.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetZonesZoneResult> Zones;

        [OutputConstructor]
        private GetZonesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetZonesFilterResult> filters,

            string id,

            string? name,

            string? nameContains,

            string? scope,

            string? sortBy,

            string? sortOrder,

            string? state,

            string? timeCreatedGreaterThanOrEqualTo,

            string? timeCreatedLessThan,

            string? tsigKeyId,

            string? viewId,

            string? zoneType,

            ImmutableArray<Outputs.GetZonesZoneResult> zones)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            NameContains = nameContains;
            Scope = scope;
            SortBy = sortBy;
            SortOrder = sortOrder;
            State = state;
            TimeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            TimeCreatedLessThan = timeCreatedLessThan;
            TsigKeyId = tsigKeyId;
            ViewId = viewId;
            ZoneType = zoneType;
            Zones = zones;
        }
    }
}