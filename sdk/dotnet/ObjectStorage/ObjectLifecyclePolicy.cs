// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    /// <summary>
    /// This resource provides the Object Lifecycle Policy resource in Oracle Cloud Infrastructure Object Storage service.
    /// 
    /// Creates or replaces the object lifecycle policy for the bucket.
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
    ///         var testObjectLifecyclePolicy = new Oci.ObjectStorage.ObjectLifecyclePolicy("testObjectLifecyclePolicy", new Oci.ObjectStorage.ObjectLifecyclePolicyArgs
    ///         {
    ///             Bucket = @var.Object_lifecycle_policy_bucket,
    ///             Namespace = @var.Object_lifecycle_policy_namespace,
    ///             Rules = 
    ///             {
    ///                 new Oci.ObjectStorage.Inputs.ObjectLifecyclePolicyRuleArgs
    ///                 {
    ///                     Action = @var.Object_lifecycle_policy_rules_action,
    ///                     IsEnabled = @var.Object_lifecycle_policy_rules_is_enabled,
    ///                     Name = @var.Object_lifecycle_policy_rules_name,
    ///                     TimeAmount = @var.Object_lifecycle_policy_rules_time_amount,
    ///                     TimeUnit = @var.Object_lifecycle_policy_rules_time_unit,
    ///                     ObjectNameFilter = new Oci.ObjectStorage.Inputs.ObjectLifecyclePolicyRuleObjectNameFilterArgs
    ///                     {
    ///                         ExclusionPatterns = @var.Object_lifecycle_policy_rules_object_name_filter_exclusion_patterns,
    ///                         InclusionPatterns = @var.Object_lifecycle_policy_rules_object_name_filter_inclusion_patterns,
    ///                         InclusionPrefixes = @var.Object_lifecycle_policy_rules_object_name_filter_inclusion_prefixes,
    ///                     },
    ///                     Target = @var.Object_lifecycle_policy_rules_target,
    ///                 },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ObjectLifecyclePolicies can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy test_object_lifecycle_policy "n/{namespaceName}/b/{bucketName}/l"
    /// ```
    /// </summary>
    [OciResourceType("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy")]
    public partial class ObjectLifecyclePolicy : Pulumi.CustomResource
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Output("bucket")]
        public Output<string> Bucket { get; private set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The bucket's set of lifecycle policy rules.
        /// </summary>
        [Output("rules")]
        public Output<ImmutableArray<Outputs.ObjectLifecyclePolicyRule>> Rules { get; private set; } = null!;

        /// <summary>
        /// The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a ObjectLifecyclePolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ObjectLifecyclePolicy(string name, ObjectLifecyclePolicyArgs args, CustomResourceOptions? options = null)
            : base("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy", name, args ?? new ObjectLifecyclePolicyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ObjectLifecyclePolicy(string name, Input<string> id, ObjectLifecyclePolicyState? state = null, CustomResourceOptions? options = null)
            : base("oci:ObjectStorage/objectLifecyclePolicy:ObjectLifecyclePolicy", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ObjectLifecyclePolicy resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ObjectLifecyclePolicy Get(string name, Input<string> id, ObjectLifecyclePolicyState? state = null, CustomResourceOptions? options = null)
        {
            return new ObjectLifecyclePolicy(name, id, state, options);
        }
    }

    public sealed class ObjectLifecyclePolicyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        [Input("rules")]
        private InputList<Inputs.ObjectLifecyclePolicyRuleArgs>? _rules;

        /// <summary>
        /// (Updatable) The bucket's set of lifecycle policy rules.
        /// </summary>
        public InputList<Inputs.ObjectLifecyclePolicyRuleArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.ObjectLifecyclePolicyRuleArgs>());
            set => _rules = value;
        }

        public ObjectLifecyclePolicyArgs()
        {
        }
    }

    public sealed class ObjectLifecyclePolicyState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("bucket")]
        public Input<string>? Bucket { get; set; }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        [Input("rules")]
        private InputList<Inputs.ObjectLifecyclePolicyRuleGetArgs>? _rules;

        /// <summary>
        /// (Updatable) The bucket's set of lifecycle policy rules.
        /// </summary>
        public InputList<Inputs.ObjectLifecyclePolicyRuleGetArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.ObjectLifecyclePolicyRuleGetArgs>());
            set => _rules = value;
        }

        /// <summary>
        /// The date and time the object lifecycle policy was created, as described in [RFC 3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public ObjectLifecyclePolicyState()
        {
        }
    }
}
