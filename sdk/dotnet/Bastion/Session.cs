// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bastion
{
    /// <summary>
    /// This resource provides the Session resource in Oracle Cloud Infrastructure Bastion service.
    /// 
    /// Creates a new session in a bastion. A bastion session lets authorized users connect to a target resource for a predetermined amount of time. The Bastion service recognizes two types of sessions, managed SSH sessions and SSH port forwarding sessions. Managed SSH sessions require that the target resource has an OpenSSH server and the Oracle Cloud Agent both running.
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
    ///     var testSession = new Oci.Bastion.Session("testSession", new()
    ///     {
    ///         BastionId = oci_bastion_bastion.Test_bastion.Id,
    ///         KeyDetails = new Oci.Bastion.Inputs.SessionKeyDetailsArgs
    ///         {
    ///             PublicKeyContent = @var.Session_key_details_public_key_content,
    ///         },
    ///         TargetResourceDetails = new Oci.Bastion.Inputs.SessionTargetResourceDetailsArgs
    ///         {
    ///             SessionType = @var.Session_target_resource_details_session_type,
    ///             TargetResourceId = oci_bastion_target_resource.Test_target_resource.Id,
    ///             TargetResourceOperatingSystemUserName = oci_identity_user.Test_user.Name,
    ///             TargetResourcePort = @var.Session_target_resource_details_target_resource_port,
    ///             TargetResourcePrivateIpAddress = @var.Session_target_resource_details_target_resource_private_ip_address,
    ///         },
    ///         DisplayName = @var.Session_display_name,
    ///         KeyType = @var.Session_key_type,
    ///         SessionTtlInSeconds = @var.Session_session_ttl_in_seconds,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Sessions can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Bastion/session:Session test_session "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Bastion/session:Session")]
    public partial class Session : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The unique identifier (OCID) of the bastion on which to create this session.
        /// </summary>
        [Output("bastionId")]
        public Output<string> BastionId { get; private set; } = null!;

        /// <summary>
        /// The name of the bastion that is hosting this session.
        /// </summary>
        [Output("bastionName")]
        public Output<string> BastionName { get; private set; } = null!;

        /// <summary>
        /// The public key of the bastion host. You can use this to verify that you're connecting to the correct bastion.
        /// </summary>
        [Output("bastionPublicHostKeyInfo")]
        public Output<string> BastionPublicHostKeyInfo { get; private set; } = null!;

        /// <summary>
        /// The username that the session uses to connect to the target resource.
        /// </summary>
        [Output("bastionUserName")]
        public Output<string> BastionUserName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the session.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Public key details for a bastion session.
        /// </summary>
        [Output("keyDetails")]
        public Output<Outputs.SessionKeyDetails> KeyDetails { get; private set; } = null!;

        /// <summary>
        /// The type of the key used to connect to the session. PUB is a standard public key in OpenSSH format.
        /// </summary>
        [Output("keyType")]
        public Output<string> KeyType { get; private set; } = null!;

        /// <summary>
        /// A message describing the current session state in more detail.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The amount of time the session can remain active.
        /// </summary>
        [Output("sessionTtlInSeconds")]
        public Output<int> SessionTtlInSeconds { get; private set; } = null!;

        /// <summary>
        /// The connection message for the session.
        /// </summary>
        [Output("sshMetadata")]
        public Output<ImmutableDictionary<string, object>> SshMetadata { get; private set; } = null!;

        /// <summary>
        /// The current state of the session.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Details about a bastion session's target resource.
        /// </summary>
        [Output("targetResourceDetails")]
        public Output<Outputs.SessionTargetResourceDetails> TargetResourceDetails { get; private set; } = null!;

        /// <summary>
        /// The time the session was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the session was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a Session resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Session(string name, SessionArgs args, CustomResourceOptions? options = null)
            : base("oci:Bastion/session:Session", name, args ?? new SessionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Session(string name, Input<string> id, SessionState? state = null, CustomResourceOptions? options = null)
            : base("oci:Bastion/session:Session", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Session resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Session Get(string name, Input<string> id, SessionState? state = null, CustomResourceOptions? options = null)
        {
            return new Session(name, id, state, options);
        }
    }

    public sealed class SessionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the bastion on which to create this session.
        /// </summary>
        [Input("bastionId", required: true)]
        public Input<string> BastionId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The name of the session.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Public key details for a bastion session.
        /// </summary>
        [Input("keyDetails", required: true)]
        public Input<Inputs.SessionKeyDetailsArgs> KeyDetails { get; set; } = null!;

        /// <summary>
        /// The type of the key used to connect to the session. PUB is a standard public key in OpenSSH format.
        /// </summary>
        [Input("keyType")]
        public Input<string>? KeyType { get; set; }

        /// <summary>
        /// The amount of time the session can remain active.
        /// </summary>
        [Input("sessionTtlInSeconds")]
        public Input<int>? SessionTtlInSeconds { get; set; }

        /// <summary>
        /// Details about a bastion session's target resource.
        /// </summary>
        [Input("targetResourceDetails", required: true)]
        public Input<Inputs.SessionTargetResourceDetailsArgs> TargetResourceDetails { get; set; } = null!;

        public SessionArgs()
        {
        }
        public static new SessionArgs Empty => new SessionArgs();
    }

    public sealed class SessionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the bastion on which to create this session.
        /// </summary>
        [Input("bastionId")]
        public Input<string>? BastionId { get; set; }

        /// <summary>
        /// The name of the bastion that is hosting this session.
        /// </summary>
        [Input("bastionName")]
        public Input<string>? BastionName { get; set; }

        /// <summary>
        /// The public key of the bastion host. You can use this to verify that you're connecting to the correct bastion.
        /// </summary>
        [Input("bastionPublicHostKeyInfo")]
        public Input<string>? BastionPublicHostKeyInfo { get; set; }

        /// <summary>
        /// The username that the session uses to connect to the target resource.
        /// </summary>
        [Input("bastionUserName")]
        public Input<string>? BastionUserName { get; set; }

        /// <summary>
        /// (Updatable) The name of the session.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Public key details for a bastion session.
        /// </summary>
        [Input("keyDetails")]
        public Input<Inputs.SessionKeyDetailsGetArgs>? KeyDetails { get; set; }

        /// <summary>
        /// The type of the key used to connect to the session. PUB is a standard public key in OpenSSH format.
        /// </summary>
        [Input("keyType")]
        public Input<string>? KeyType { get; set; }

        /// <summary>
        /// A message describing the current session state in more detail.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The amount of time the session can remain active.
        /// </summary>
        [Input("sessionTtlInSeconds")]
        public Input<int>? SessionTtlInSeconds { get; set; }

        [Input("sshMetadata")]
        private InputMap<object>? _sshMetadata;

        /// <summary>
        /// The connection message for the session.
        /// </summary>
        public InputMap<object> SshMetadata
        {
            get => _sshMetadata ?? (_sshMetadata = new InputMap<object>());
            set => _sshMetadata = value;
        }

        /// <summary>
        /// The current state of the session.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Details about a bastion session's target resource.
        /// </summary>
        [Input("targetResourceDetails")]
        public Input<Inputs.SessionTargetResourceDetailsGetArgs>? TargetResourceDetails { get; set; }

        /// <summary>
        /// The time the session was created. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the session was updated. Format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2020-01-25T21:10:29.600Z`
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public SessionState()
        {
        }
        public static new SessionState Empty => new SessionState();
    }
}