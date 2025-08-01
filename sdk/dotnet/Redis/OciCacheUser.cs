// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Redis
{
    /// <summary>
    /// This resource provides the Oci Cache User resource in Oracle Cloud Infrastructure Redis service.
    /// 
    /// Creates a new Oracle Cloud Infrastructure Cache user. Oracle Cloud Infrastructure Cache user is required to authenticate to Oracle Cloud Infrastructure Cache cluster.
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
    ///     var testOciCacheUser = new Oci.Redis.OciCacheUser("test_oci_cache_user", new()
    ///     {
    ///         AclString = ociCacheUserAclString,
    ///         AuthenticationMode = new Oci.Redis.Inputs.OciCacheUserAuthenticationModeArgs
    ///         {
    ///             AuthenticationType = ociCacheUserAuthenticationModeAuthenticationType,
    ///             HashedPasswords = ociCacheUserAuthenticationModeHashedPasswords,
    ///         },
    ///         CompartmentId = compartmentId,
    ///         Description = ociCacheUserDescription,
    ///         Name = ociCacheUserName,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         Status = ociCacheUserStatus,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OciCacheUsers can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Redis/ociCacheUser:OciCacheUser test_oci_cache_user "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Redis/ociCacheUser:OciCacheUser")]
    public partial class OciCacheUser : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Output("aclString")]
        public Output<string> AclString { get; private set; } = null!;

        /// <summary>
        /// (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Output("authenticationMode")]
        public Output<Outputs.OciCacheUserAuthenticationMode> AuthenticationMode { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// Oracle Cloud Infrastructure Cache user lifecycle state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time, when the Oracle Cloud Infrastructure cache user was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a OciCacheUser resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OciCacheUser(string name, OciCacheUserArgs args, CustomResourceOptions? options = null)
            : base("oci:Redis/ociCacheUser:OciCacheUser", name, args ?? new OciCacheUserArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OciCacheUser(string name, Input<string> id, OciCacheUserState? state = null, CustomResourceOptions? options = null)
            : base("oci:Redis/ociCacheUser:OciCacheUser", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OciCacheUser resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OciCacheUser Get(string name, Input<string> id, OciCacheUserState? state = null, CustomResourceOptions? options = null)
        {
            return new OciCacheUser(name, id, state, options);
        }
    }

    public sealed class OciCacheUserArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("aclString", required: true)]
        public Input<string> AclString { get; set; } = null!;

        /// <summary>
        /// (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("authenticationMode", required: true)]
        public Input<Inputs.OciCacheUserAuthenticationModeArgs> AuthenticationMode { get; set; } = null!;

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
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
        /// (Updatable) Description of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("description", required: true)]
        public Input<string> Description { get; set; } = null!;

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
        /// Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        public OciCacheUserArgs()
        {
        }
        public static new OciCacheUserArgs Empty => new OciCacheUserArgs();
    }

    public sealed class OciCacheUserState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) ACL string of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("aclString")]
        public Input<string>? AclString { get; set; }

        /// <summary>
        /// (Updatable) These are the Authentication details of an Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("authenticationMode")]
        public Input<Inputs.OciCacheUserAuthenticationModeGetArgs>? AuthenticationMode { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user compartment ID.
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
        /// (Updatable) Description of Oracle Cloud Infrastructure cache user.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

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
        /// Oracle Cloud Infrastructure cache user name is required to connect to an Oracle Cloud Infrastructure cache cluster.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Oracle Cloud Infrastructure Cache user lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure cache user status. ON enables and OFF disables the Oracle Cloud Infrastructure cache user to login to the associated clusters. Default value is ON.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time, when the Oracle Cloud Infrastructure cache user was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time, when the Oracle Cloud Infrastructure cache user was updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public OciCacheUserState()
        {
        }
        public static new OciCacheUserState Empty => new OciCacheUserState();
    }
}
