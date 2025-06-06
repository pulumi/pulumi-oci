// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Execution Window resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates an execution window resource.
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
    ///     var testExecutionWindow = new Oci.Database.ExecutionWindow("test_execution_window", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         ExecutionResourceId = testResource.Id,
    ///         TimeScheduled = executionWindowTimeScheduled,
    ///         WindowDurationInMins = executionWindowWindowDurationInMins,
    ///         DefinedTags = executionWindowDefinedTags,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         IsEnforcedDuration = executionWindowIsEnforcedDuration,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// ExecutionWindows can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Database/executionWindow:ExecutionWindow test_execution_window "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Database/executionWindow:ExecutionWindow")]
    public partial class ExecutionWindow : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// Description of the execution window.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the execution window. The name does not need to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The estimated time of the execution window in minutes.
        /// </summary>
        [Output("estimatedTimeInMins")]
        public Output<int> EstimatedTimeInMins { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
        /// </summary>
        [Output("executionResourceId")]
        public Output<string> ExecutionResourceId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
        /// </summary>
        [Output("isEnforcedDuration")]
        public Output<bool> IsEnforcedDuration { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
        /// </summary>
        [Output("lifecycleSubstate")]
        public Output<string> LifecycleSubstate { get; private set; } = null!;

        /// <summary>
        /// The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the execution window was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time that the execution window ended.
        /// </summary>
        [Output("timeEnded")]
        public Output<string> TimeEnded { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The scheduled start date and time of the execution window.
        /// </summary>
        [Output("timeScheduled")]
        public Output<string> TimeScheduled { get; private set; } = null!;

        /// <summary>
        /// The date and time that the execution window was started.
        /// </summary>
        [Output("timeStarted")]
        public Output<string> TimeStarted { get; private set; } = null!;

        /// <summary>
        /// The last date and time that the execution window was updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// The total time taken by corresponding resource activity in minutes.
        /// </summary>
        [Output("totalTimeTakenInMins")]
        public Output<int> TotalTimeTakenInMins { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("windowDurationInMins")]
        public Output<int> WindowDurationInMins { get; private set; } = null!;

        /// <summary>
        /// The execution window is of PLANNED or UNPLANNED type.
        /// </summary>
        [Output("windowType")]
        public Output<string> WindowType { get; private set; } = null!;


        /// <summary>
        /// Create a ExecutionWindow resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExecutionWindow(string name, ExecutionWindowArgs args, CustomResourceOptions? options = null)
            : base("oci:Database/executionWindow:ExecutionWindow", name, args ?? new ExecutionWindowArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExecutionWindow(string name, Input<string> id, ExecutionWindowState? state = null, CustomResourceOptions? options = null)
            : base("oci:Database/executionWindow:ExecutionWindow", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExecutionWindow resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExecutionWindow Get(string name, Input<string> id, ExecutionWindowState? state = null, CustomResourceOptions? options = null)
        {
            return new ExecutionWindow(name, id, state, options);
        }
    }

    public sealed class ExecutionWindowArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
        /// </summary>
        [Input("executionResourceId", required: true)]
        public Input<string> ExecutionResourceId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
        /// </summary>
        [Input("isEnforcedDuration")]
        public Input<bool>? IsEnforcedDuration { get; set; }

        /// <summary>
        /// (Updatable) The scheduled start date and time of the execution window.
        /// </summary>
        [Input("timeScheduled", required: true)]
        public Input<string> TimeScheduled { get; set; } = null!;

        /// <summary>
        /// (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("windowDurationInMins", required: true)]
        public Input<int> WindowDurationInMins { get; set; } = null!;

        public ExecutionWindowArgs()
        {
        }
        public static new ExecutionWindowArgs Empty => new ExecutionWindowArgs();
    }

    public sealed class ExecutionWindowState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// Description of the execution window.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The user-friendly name for the execution window. The name does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The estimated time of the execution window in minutes.
        /// </summary>
        [Input("estimatedTimeInMins")]
        public Input<int>? EstimatedTimeInMins { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution resource the execution window belongs to.
        /// </summary>
        [Input("executionResourceId")]
        public Input<string>? ExecutionResourceId { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) Indicates if duration the user plans to allocate for scheduling window is strictly enforced. The default value is `FALSE`.
        /// </summary>
        [Input("isEnforcedDuration")]
        public Input<bool>? IsEnforcedDuration { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The current sub-state of the execution window. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
        /// </summary>
        [Input("lifecycleSubstate")]
        public Input<string>? LifecycleSubstate { get; set; }

        /// <summary>
        /// The current state of the Schedule Policy. Valid states are CREATED, SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the execution window was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time that the execution window ended.
        /// </summary>
        [Input("timeEnded")]
        public Input<string>? TimeEnded { get; set; }

        /// <summary>
        /// (Updatable) The scheduled start date and time of the execution window.
        /// </summary>
        [Input("timeScheduled")]
        public Input<string>? TimeScheduled { get; set; }

        /// <summary>
        /// The date and time that the execution window was started.
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        /// <summary>
        /// The last date and time that the execution window was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// The total time taken by corresponding resource activity in minutes.
        /// </summary>
        [Input("totalTimeTakenInMins")]
        public Input<int>? TotalTimeTakenInMins { get; set; }

        /// <summary>
        /// (Updatable) Duration window allows user to set a duration they plan to allocate for Scheduling window. The duration is in minutes. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("windowDurationInMins")]
        public Input<int>? WindowDurationInMins { get; set; }

        /// <summary>
        /// The execution window is of PLANNED or UNPLANNED type.
        /// </summary>
        [Input("windowType")]
        public Input<string>? WindowType { get; set; }

        public ExecutionWindowState()
        {
        }
        public static new ExecutionWindowState Empty => new ExecutionWindowState();
    }
}
