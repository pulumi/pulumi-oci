// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement
{
    /// <summary>
    /// This resource provides the Maintenance Window resource in Oracle Cloud Infrastructure Fleet Apps Management service.
    /// 
    /// Create a maintenance window in Fleet Application Management.
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
    ///     var testMaintenanceWindow = new Oci.FleetAppsManagement.MaintenanceWindow("test_maintenance_window", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         Duration = maintenanceWindowDuration,
    ///         TimeScheduleStart = maintenanceWindowTimeScheduleStart,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = maintenanceWindowDescription,
    ///         DisplayName = maintenanceWindowDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IsOutage = maintenanceWindowIsOutage,
    ///         IsRecurring = maintenanceWindowIsRecurring,
    ///         Recurrences = maintenanceWindowRecurrences,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// MaintenanceWindows can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:FleetAppsManagement/maintenanceWindow:MaintenanceWindow test_maintenance_window "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:FleetAppsManagement/maintenanceWindow:MaintenanceWindow")]
    public partial class MaintenanceWindow : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Compartment OCID
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Duration of the maintenance window. Specify how long the maintenance window remains open.
        /// </summary>
        [Output("duration")]
        public Output<string> Duration { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Does the maintenenace window cause outage? An outage indicates whether a maintenance window can consider operations that require downtime. It means a period when the application is not accessible.
        /// </summary>
        [Output("isOutage")]
        public Output<bool> IsOutage { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Is this a recurring maintenance window?
        /// </summary>
        [Output("isRecurring")]
        public Output<bool> IsRecurring { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Recurrence rule specification if maintenance window recurring. Specify the frequency of running the maintenance window.
        /// </summary>
        [Output("recurrences")]
        public Output<string> Recurrences { get; private set; } = null!;

        /// <summary>
        /// Associated region
        /// </summary>
        [Output("resourceRegion")]
        public Output<string> ResourceRegion { get; private set; } = null!;

        /// <summary>
        /// The current state of the MaintenanceWindow.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specify the date and time of the day that the maintenance window starts.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("timeScheduleStart")]
        public Output<string> TimeScheduleStart { get; private set; } = null!;

        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a MaintenanceWindow resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MaintenanceWindow(string name, MaintenanceWindowArgs args, CustomResourceOptions? options = null)
            : base("oci:FleetAppsManagement/maintenanceWindow:MaintenanceWindow", name, args ?? new MaintenanceWindowArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MaintenanceWindow(string name, Input<string> id, MaintenanceWindowState? state = null, CustomResourceOptions? options = null)
            : base("oci:FleetAppsManagement/maintenanceWindow:MaintenanceWindow", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing MaintenanceWindow resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MaintenanceWindow Get(string name, Input<string> id, MaintenanceWindowState? state = null, CustomResourceOptions? options = null)
        {
            return new MaintenanceWindow(name, id, state, options);
        }
    }

    public sealed class MaintenanceWindowArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Compartment OCID
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) Duration of the maintenance window. Specify how long the maintenance window remains open.
        /// </summary>
        [Input("duration", required: true)]
        public Input<string> Duration { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Does the maintenenace window cause outage? An outage indicates whether a maintenance window can consider operations that require downtime. It means a period when the application is not accessible.
        /// </summary>
        [Input("isOutage")]
        public Input<bool>? IsOutage { get; set; }

        /// <summary>
        /// (Updatable) Is this a recurring maintenance window?
        /// </summary>
        [Input("isRecurring")]
        public Input<bool>? IsRecurring { get; set; }

        /// <summary>
        /// (Updatable) Recurrence rule specification if maintenance window recurring. Specify the frequency of running the maintenance window.
        /// </summary>
        [Input("recurrences")]
        public Input<string>? Recurrences { get; set; }

        /// <summary>
        /// (Updatable) Specify the date and time of the day that the maintenance window starts.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeScheduleStart", required: true)]
        public Input<string> TimeScheduleStart { get; set; } = null!;

        public MaintenanceWindowArgs()
        {
        }
        public static new MaintenanceWindowArgs Empty => new MaintenanceWindowArgs();
    }

    public sealed class MaintenanceWindowState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Compartment OCID
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly description. To provide some insight about the resource. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) Duration of the maintenance window. Specify how long the maintenance window remains open.
        /// </summary>
        [Input("duration")]
        public Input<string>? Duration { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Does the maintenenace window cause outage? An outage indicates whether a maintenance window can consider operations that require downtime. It means a period when the application is not accessible.
        /// </summary>
        [Input("isOutage")]
        public Input<bool>? IsOutage { get; set; }

        /// <summary>
        /// (Updatable) Is this a recurring maintenance window?
        /// </summary>
        [Input("isRecurring")]
        public Input<bool>? IsRecurring { get; set; }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// (Updatable) Recurrence rule specification if maintenance window recurring. Specify the frequency of running the maintenance window.
        /// </summary>
        [Input("recurrences")]
        public Input<string>? Recurrences { get; set; }

        /// <summary>
        /// Associated region
        /// </summary>
        [Input("resourceRegion")]
        public Input<string>? ResourceRegion { get; set; }

        /// <summary>
        /// The current state of the MaintenanceWindow.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time this resource was created. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// (Updatable) Specify the date and time of the day that the maintenance window starts.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeScheduleStart")]
        public Input<string>? TimeScheduleStart { get; set; }

        /// <summary>
        /// The time this resource was last updated. An RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public MaintenanceWindowState()
        {
        }
        public static new MaintenanceWindowState Empty => new MaintenanceWindowState();
    }
}
