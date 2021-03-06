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
    /// This resource provides the Authentication Policy resource in Oracle Cloud Infrastructure Identity service.
    /// 
    /// Updates authentication policy for the specified tenancy
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
    ///         var testAuthenticationPolicy = new Oci.Identity.AuthenticationPolicy("testAuthenticationPolicy", new Oci.Identity.AuthenticationPolicyArgs
    ///         {
    ///             CompartmentId = @var.Tenancy_ocid,
    ///             NetworkPolicy = new Oci.Identity.Inputs.AuthenticationPolicyNetworkPolicyArgs
    ///             {
    ///                 NetworkSourceIds = @var.Authentication_policy_network_policy_network_source_ids,
    ///             },
    ///             PasswordPolicy = new Oci.Identity.Inputs.AuthenticationPolicyPasswordPolicyArgs
    ///             {
    ///                 IsLowercaseCharactersRequired = @var.Authentication_policy_password_policy_is_lowercase_characters_required,
    ///                 IsNumericCharactersRequired = @var.Authentication_policy_password_policy_is_numeric_characters_required,
    ///                 IsSpecialCharactersRequired = @var.Authentication_policy_password_policy_is_special_characters_required,
    ///                 IsUppercaseCharactersRequired = @var.Authentication_policy_password_policy_is_uppercase_characters_required,
    ///                 IsUsernameContainmentAllowed = @var.Authentication_policy_password_policy_is_username_containment_allowed,
    ///                 MinimumPasswordLength = @var.Authentication_policy_password_policy_minimum_password_length,
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// AuthenticationPolicies can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Identity/authenticationPolicy:AuthenticationPolicy test_authentication_policy "authenticationPolicies/{compartmentId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Identity/authenticationPolicy:AuthenticationPolicy")]
    public partial class AuthenticationPolicy : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Network policy, Consists of a list of Network Source ids.
        /// </summary>
        [Output("networkPolicy")]
        public Output<Outputs.AuthenticationPolicyNetworkPolicy> NetworkPolicy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Password policy, currently set for the given compartment.
        /// </summary>
        [Output("passwordPolicy")]
        public Output<Outputs.AuthenticationPolicyPasswordPolicy> PasswordPolicy { get; private set; } = null!;


        /// <summary>
        /// Create a AuthenticationPolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AuthenticationPolicy(string name, AuthenticationPolicyArgs args, CustomResourceOptions? options = null)
            : base("oci:Identity/authenticationPolicy:AuthenticationPolicy", name, args ?? new AuthenticationPolicyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AuthenticationPolicy(string name, Input<string> id, AuthenticationPolicyState? state = null, CustomResourceOptions? options = null)
            : base("oci:Identity/authenticationPolicy:AuthenticationPolicy", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing AuthenticationPolicy resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AuthenticationPolicy Get(string name, Input<string> id, AuthenticationPolicyState? state = null, CustomResourceOptions? options = null)
        {
            return new AuthenticationPolicy(name, id, state, options);
        }
    }

    public sealed class AuthenticationPolicyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Network policy, Consists of a list of Network Source ids.
        /// </summary>
        [Input("networkPolicy")]
        public Input<Inputs.AuthenticationPolicyNetworkPolicyArgs>? NetworkPolicy { get; set; }

        /// <summary>
        /// (Updatable) Password policy, currently set for the given compartment.
        /// </summary>
        [Input("passwordPolicy")]
        public Input<Inputs.AuthenticationPolicyPasswordPolicyArgs>? PasswordPolicy { get; set; }

        public AuthenticationPolicyArgs()
        {
        }
    }

    public sealed class AuthenticationPolicyState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Network policy, Consists of a list of Network Source ids.
        /// </summary>
        [Input("networkPolicy")]
        public Input<Inputs.AuthenticationPolicyNetworkPolicyGetArgs>? NetworkPolicy { get; set; }

        /// <summary>
        /// (Updatable) Password policy, currently set for the given compartment.
        /// </summary>
        [Input("passwordPolicy")]
        public Input<Inputs.AuthenticationPolicyPasswordPolicyGetArgs>? PasswordPolicy { get; set; }

        public AuthenticationPolicyState()
        {
        }
    }
}
