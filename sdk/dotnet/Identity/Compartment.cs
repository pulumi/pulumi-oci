// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    /// <summary>
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testCompartment = new Oci.Identity.Compartment("testCompartment", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         Description = @var.Compartment_description,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Compartments can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Identity/compartment:Compartment test_compartment "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Identity/compartment:Compartment")]
    public partial class Compartment : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the parent compartment containing the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
        /// </summary>
        [Output("enableDelete")]
        public Output<bool?> EnableDelete { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Output("inactiveState")]
        public Output<string> InactiveState { get; private set; } = null!;

        /// <summary>
        /// Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
        /// </summary>
        [Output("isAccessible")]
        public Output<bool> IsAccessible { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The compartment's current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a Compartment resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Compartment(string name, CompartmentArgs args, CustomResourceOptions? options = null)
            : base("oci:Identity/compartment:Compartment", name, args ?? new CompartmentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Compartment(string name, Input<string> id, CompartmentState? state = null, CustomResourceOptions? options = null)
            : base("oci:Identity/compartment:Compartment", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Compartment resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Compartment Get(string name, Input<string> id, CompartmentState? state = null, CustomResourceOptions? options = null)
        {
            return new Compartment(name, id, state, options);
        }
    }

    public sealed class CompartmentArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the parent compartment containing the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Input("description", required: true)]
        public Input<string> Description { get; set; } = null!;

        /// <summary>
        /// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
        /// </summary>
        [Input("enableDelete")]
        public Input<bool>? EnableDelete { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public CompartmentArgs()
        {
        }
        public static new CompartmentArgs Empty => new CompartmentArgs();
    }

    public sealed class CompartmentState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the parent compartment containing the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description you assign to the compartment during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Defaults to false. If omitted or set to false the provider will implicitly import the compartment if there is a name collision, and will not actually delete the compartment on destroy or removal of the resource declaration. If set to true, the provider will throw an error on a name collision with another compartment, and will attempt to delete the compartment on destroy or removal of the resource declaration.
        /// </summary>
        [Input("enableDelete")]
        public Input<bool>? EnableDelete { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Input("inactiveState")]
        public Input<string>? InactiveState { get; set; }

        /// <summary>
        /// Indicates whether or not the compartment is accessible for the user making the request. Returns true when the user has INSPECT permissions directly on a resource in the compartment or indirectly (permissions can be on a resource in a subcompartment).
        /// </summary>
        [Input("isAccessible")]
        public Input<bool>? IsAccessible { get; set; }

        /// <summary>
        /// (Updatable) The name you assign to the compartment during creation. The name must be unique across all compartments in the parent compartment. Avoid entering confidential information.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The compartment's current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Date and time the compartment was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public CompartmentState()
        {
        }
        public static new CompartmentState Empty => new CompartmentState();
    }
}