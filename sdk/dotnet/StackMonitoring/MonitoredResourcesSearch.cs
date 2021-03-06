// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    /// <summary>
    /// This resource provides the Monitored Resources Search resource in Oracle Cloud Infrastructure Stack Monitoring service.
    /// 
    /// Returns a list of monitored resources.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testMonitoredResourcesSearch = new Oci.StackMonitoring.MonitoredResourcesSearch("testMonitoredResourcesSearch", new Oci.StackMonitoring.MonitoredResourcesSearchArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             HostName = @var.Monitored_resources_search_host_name,
    ///             HostNameContains = @var.Monitored_resources_search_host_name_contains,
    ///             ManagementAgentId = oci_management_agent_management_agent.Test_management_agent.Id,
    ///             NameContains = @var.Monitored_resources_search_name_contains,
    ///             PropertyEquals = @var.Monitored_resources_search_property_equals,
    ///             ResourceTimeZone = @var.Monitored_resources_search_resource_time_zone,
    ///             State = @var.Monitored_resources_search_state,
    ///             TimeCreatedGreaterThanOrEqualTo = @var.Monitored_resources_search_time_created_greater_than_or_equal_to,
    ///             TimeCreatedLessThan = @var.Monitored_resources_search_time_created_less_than,
    ///             TimeUpdatedGreaterThanOrEqualTo = @var.Monitored_resources_search_time_updated_greater_than_or_equal_to,
    ///             TimeUpdatedLessThan = @var.Monitored_resources_search_time_updated_less_than,
    ///             Type = @var.Monitored_resources_search_type,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// MonitoredResourcesSearch can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:StackMonitoring/monitoredResourcesSearch:MonitoredResourcesSearch test_monitored_resources_search "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:StackMonitoring/monitoredResourcesSearch:MonitoredResourcesSearch")]
    public partial class MonitoredResourcesSearch : Pulumi.CustomResource
    {
        /// <summary>
        /// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources with host name match
        /// </summary>
        [Output("hostName")]
        public Output<string?> HostName { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources with host name pattern
        /// </summary>
        [Output("hostNameContains")]
        public Output<string?> HostNameContains { get; private set; } = null!;

        /// <summary>
        /// List of monitored resources.
        /// </summary>
        [Output("items")]
        public Output<ImmutableArray<Outputs.MonitoredResourcesSearchItem>> Items { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources with matching management agent id.
        /// </summary>
        [Output("managementAgentId")]
        public Output<string?> ManagementAgentId { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources that match exact resource name
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources that match resource name pattern given. The match is not case sensitive.
        /// </summary>
        [Output("nameContains")]
        public Output<string?> NameContains { get; private set; } = null!;

        /// <summary>
        /// Criteria based on resource property.
        /// </summary>
        [Output("propertyEquals")]
        public Output<ImmutableDictionary<string, object>?> PropertyEquals { get; private set; } = null!;

        /// <summary>
        /// Time zone in the form of tz database canonical zone ID.
        /// </summary>
        [Output("resourceTimeZone")]
        public Output<string?> ResourceTimeZone { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources with matching lifecycle state.
        /// </summary>
        [Output("state")]
        public Output<string?> State { get; private set; } = null!;

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the earliest creation date for the returned list (inclusive). Specifying this parameter without the corresponding `timeCreatedLessThan` parameter will retrieve resources created from the given `timeCreatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreatedGreaterThanOrEqualTo")]
        public Output<string?> TimeCreatedGreaterThanOrEqualTo { get; private set; } = null!;

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all resources created before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreatedLessThan")]
        public Output<string?> TimeCreatedLessThan { get; private set; } = null!;

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the earliest update date for the returned list (inclusive). Specifying this parameter without the corresponding `timeUpdatedLessThan` parameter will retrieve resources updated from the given `timeUpdatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeUpdatedGreaterThanOrEqualTo")]
        public Output<string?> TimeUpdatedGreaterThanOrEqualTo { get; private set; } = null!;

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeUpdatedLessThan")]
        public Output<string?> TimeUpdatedLessThan { get; private set; } = null!;

        /// <summary>
        /// A filter to return resources that match resource type
        /// </summary>
        [Output("type")]
        public Output<string?> Type { get; private set; } = null!;


        /// <summary>
        /// Create a MonitoredResourcesSearch resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MonitoredResourcesSearch(string name, MonitoredResourcesSearchArgs args, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoredResourcesSearch:MonitoredResourcesSearch", name, args ?? new MonitoredResourcesSearchArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MonitoredResourcesSearch(string name, Input<string> id, MonitoredResourcesSearchState? state = null, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoredResourcesSearch:MonitoredResourcesSearch", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing MonitoredResourcesSearch resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MonitoredResourcesSearch Get(string name, Input<string> id, MonitoredResourcesSearchState? state = null, CustomResourceOptions? options = null)
        {
            return new MonitoredResourcesSearch(name, id, state, options);
        }
    }

    public sealed class MonitoredResourcesSearchArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return resources with host name match
        /// </summary>
        [Input("hostName")]
        public Input<string>? HostName { get; set; }

        /// <summary>
        /// A filter to return resources with host name pattern
        /// </summary>
        [Input("hostNameContains")]
        public Input<string>? HostNameContains { get; set; }

        /// <summary>
        /// A filter to return resources with matching management agent id.
        /// </summary>
        [Input("managementAgentId")]
        public Input<string>? ManagementAgentId { get; set; }

        /// <summary>
        /// A filter to return resources that match exact resource name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return resources that match resource name pattern given. The match is not case sensitive.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        [Input("propertyEquals")]
        private InputMap<object>? _propertyEquals;

        /// <summary>
        /// Criteria based on resource property.
        /// </summary>
        public InputMap<object> PropertyEquals
        {
            get => _propertyEquals ?? (_propertyEquals = new InputMap<object>());
            set => _propertyEquals = value;
        }

        /// <summary>
        /// Time zone in the form of tz database canonical zone ID.
        /// </summary>
        [Input("resourceTimeZone")]
        public Input<string>? ResourceTimeZone { get; set; }

        /// <summary>
        /// A filter to return resources with matching lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the earliest creation date for the returned list (inclusive). Specifying this parameter without the corresponding `timeCreatedLessThan` parameter will retrieve resources created from the given `timeCreatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public Input<string>? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all resources created before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreatedLessThan")]
        public Input<string>? TimeCreatedLessThan { get; set; }

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the earliest update date for the returned list (inclusive). Specifying this parameter without the corresponding `timeUpdatedLessThan` parameter will retrieve resources updated from the given `timeUpdatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdatedGreaterThanOrEqualTo")]
        public Input<string>? TimeUpdatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdatedLessThan")]
        public Input<string>? TimeUpdatedLessThan { get; set; }

        /// <summary>
        /// A filter to return resources that match resource type
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public MonitoredResourcesSearchArgs()
        {
        }
    }

    public sealed class MonitoredResourcesSearchState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return resources with host name match
        /// </summary>
        [Input("hostName")]
        public Input<string>? HostName { get; set; }

        /// <summary>
        /// A filter to return resources with host name pattern
        /// </summary>
        [Input("hostNameContains")]
        public Input<string>? HostNameContains { get; set; }

        [Input("items")]
        private InputList<Inputs.MonitoredResourcesSearchItemGetArgs>? _items;

        /// <summary>
        /// List of monitored resources.
        /// </summary>
        public InputList<Inputs.MonitoredResourcesSearchItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.MonitoredResourcesSearchItemGetArgs>());
            set => _items = value;
        }

        /// <summary>
        /// A filter to return resources with matching management agent id.
        /// </summary>
        [Input("managementAgentId")]
        public Input<string>? ManagementAgentId { get; set; }

        /// <summary>
        /// A filter to return resources that match exact resource name
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return resources that match resource name pattern given. The match is not case sensitive.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        [Input("propertyEquals")]
        private InputMap<object>? _propertyEquals;

        /// <summary>
        /// Criteria based on resource property.
        /// </summary>
        public InputMap<object> PropertyEquals
        {
            get => _propertyEquals ?? (_propertyEquals = new InputMap<object>());
            set => _propertyEquals = value;
        }

        /// <summary>
        /// Time zone in the form of tz database canonical zone ID.
        /// </summary>
        [Input("resourceTimeZone")]
        public Input<string>? ResourceTimeZone { get; set; }

        /// <summary>
        /// A filter to return resources with matching lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the earliest creation date for the returned list (inclusive). Specifying this parameter without the corresponding `timeCreatedLessThan` parameter will retrieve resources created from the given `timeCreatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreatedGreaterThanOrEqualTo")]
        public Input<string>? TimeCreatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for resources that were created within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeCreatedGreaterThanOrEqualTo` parameter will retrieve all resources created before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreatedLessThan")]
        public Input<string>? TimeCreatedLessThan { get; set; }

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the earliest update date for the returned list (inclusive). Specifying this parameter without the corresponding `timeUpdatedLessThan` parameter will retrieve resources updated from the given `timeUpdatedGreaterThanOrEqualTo` to the current time, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdatedGreaterThanOrEqualTo")]
        public Input<string>? TimeUpdatedGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Search for resources that were updated within a specific date range, using this parameter to specify the latest creation date for the returned list (exclusive). Specifying this parameter without the corresponding `timeUpdatedGreaterThanOrEqualTo` parameter will retrieve all resources updated before the specified end date, in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeUpdatedLessThan")]
        public Input<string>? TimeUpdatedLessThan { get; set; }

        /// <summary>
        /// A filter to return resources that match resource type
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public MonitoredResourcesSearchState()
        {
        }
    }
}
