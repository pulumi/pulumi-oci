// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    /// <summary>
    /// This resource provides the Rule Set resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Creates a new rule set associated with the specified load balancer. For more information, see
    /// [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm).
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testRuleSet = new Oci.LoadBalancer.RuleSet("testRuleSet", new()
    ///     {
    ///         Items = new[]
    ///         {
    ///             new Oci.LoadBalancer.Inputs.RuleSetItemArgs
    ///             {
    ///                 Action = @var.Rule_set_items_action,
    ///                 AllowedMethods = @var.Rule_set_items_allowed_methods,
    ///                 AreInvalidCharactersAllowed = @var.Rule_set_items_are_invalid_characters_allowed,
    ///                 Conditions = new[]
    ///                 {
    ///                     new Oci.LoadBalancer.Inputs.RuleSetItemConditionArgs
    ///                     {
    ///                         AttributeName = @var.Rule_set_items_conditions_attribute_name,
    ///                         AttributeValue = @var.Rule_set_items_conditions_attribute_value,
    ///                         Operator = @var.Rule_set_items_conditions_operator,
    ///                     },
    ///                 },
    ///                 Description = @var.Rule_set_items_description,
    ///                 Header = @var.Rule_set_items_header,
    ///                 HttpLargeHeaderSizeInKb = @var.Rule_set_items_http_large_header_size_in_kb,
    ///                 Prefix = @var.Rule_set_items_prefix,
    ///                 RedirectUri = new Oci.LoadBalancer.Inputs.RuleSetItemRedirectUriArgs
    ///                 {
    ///                     Host = @var.Rule_set_items_redirect_uri_host,
    ///                     Path = @var.Rule_set_items_redirect_uri_path,
    ///                     Port = @var.Rule_set_items_redirect_uri_port,
    ///                     Protocol = @var.Rule_set_items_redirect_uri_protocol,
    ///                     Query = @var.Rule_set_items_redirect_uri_query,
    ///                 },
    ///                 ResponseCode = @var.Rule_set_items_response_code,
    ///                 StatusCode = @var.Rule_set_items_status_code,
    ///                 Suffix = @var.Rule_set_items_suffix,
    ///                 Value = @var.Rule_set_items_value,
    ///             },
    ///         },
    ///         LoadBalancerId = oci_load_balancer_load_balancer.Test_load_balancer.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// RuleSets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:LoadBalancer/ruleSet:RuleSet test_rule_set "loadBalancers/{loadBalancerId}/ruleSets/{ruleSetName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LoadBalancer/ruleSet:RuleSet")]
    public partial class RuleSet : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
        /// </summary>
        [Output("items")]
        public Output<ImmutableArray<Outputs.RuleSetItem>> Items { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a RuleSet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public RuleSet(string name, RuleSetArgs args, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/ruleSet:RuleSet", name, args ?? new RuleSetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private RuleSet(string name, Input<string> id, RuleSetState? state = null, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/ruleSet:RuleSet", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing RuleSet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static RuleSet Get(string name, Input<string> id, RuleSetState? state = null, CustomResourceOptions? options = null)
        {
            return new RuleSet(name, id, state, options);
        }
    }

    public sealed class RuleSetArgs : global::Pulumi.ResourceArgs
    {
        [Input("items", required: true)]
        private InputList<Inputs.RuleSetItemArgs>? _items;

        /// <summary>
        /// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
        /// </summary>
        public InputList<Inputs.RuleSetItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.RuleSetItemArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public RuleSetArgs()
        {
        }
        public static new RuleSetArgs Empty => new RuleSetArgs();
    }

    public sealed class RuleSetState : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.RuleSetItemGetArgs>? _items;

        /// <summary>
        /// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
        /// </summary>
        public InputList<Inputs.RuleSetItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.RuleSetItemGetArgs>());
            set => _items = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_rule_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public RuleSetState()
        {
        }
        public static new RuleSetState Empty => new RuleSetState();
    }
}