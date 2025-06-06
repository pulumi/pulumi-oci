// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    /// <summary>
    /// This resource provides the Wlp Agent resource in Oracle Cloud Infrastructure Cloud Guard service.
    /// 
    /// Creates and registers a WLP agent for an
    /// on-premise resource.
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
    ///     var testWlpAgent = new Oci.CloudGuard.WlpAgent("test_wlp_agent", new()
    ///     {
    ///         AgentVersion = wlpAgentAgentVersion,
    ///         CertificateSignedRequest = wlpAgentCertificateSignedRequest,
    ///         CompartmentId = compartmentId,
    ///         OsInfo = wlpAgentOsInfo,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// WlpAgents can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:CloudGuard/wlpAgent:WlpAgent test_wlp_agent "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CloudGuard/wlpAgent:WlpAgent")]
    public partial class WlpAgent : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The version of the agent making the request
        /// </summary>
        [Output("agentVersion")]
        public Output<string> AgentVersion { get; private set; } = null!;

        /// <summary>
        /// The certificate ID returned by Oracle Cloud Infrastructure certificates service
        /// </summary>
        [Output("certificateId")]
        public Output<string> CertificateId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
        /// </summary>
        [Output("certificateSignedRequest")]
        public Output<string> CertificateSignedRequest { get; private set; } = null!;

        /// <summary>
        /// Compartment OCID of the host
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// OCID for instance in which WlpAgent is installed
        /// </summary>
        [Output("hostId")]
        public Output<string> HostId { get; private set; } = null!;

        /// <summary>
        /// Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("osInfo")]
        public Output<string> OsInfo { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// TenantId of the host
        /// </summary>
        [Output("tenantId")]
        public Output<string> TenantId { get; private set; } = null!;

        /// <summary>
        /// The date and time the WlpAgent was created. Format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the WlpAgent was updated. Format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a WlpAgent resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public WlpAgent(string name, WlpAgentArgs args, CustomResourceOptions? options = null)
            : base("oci:CloudGuard/wlpAgent:WlpAgent", name, args ?? new WlpAgentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private WlpAgent(string name, Input<string> id, WlpAgentState? state = null, CustomResourceOptions? options = null)
            : base("oci:CloudGuard/wlpAgent:WlpAgent", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing WlpAgent resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static WlpAgent Get(string name, Input<string> id, WlpAgentState? state = null, CustomResourceOptions? options = null)
        {
            return new WlpAgent(name, id, state, options);
        }
    }

    public sealed class WlpAgentArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The version of the agent making the request
        /// </summary>
        [Input("agentVersion", required: true)]
        public Input<string> AgentVersion { get; set; } = null!;

        /// <summary>
        /// (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
        /// </summary>
        [Input("certificateSignedRequest", required: true)]
        public Input<string> CertificateSignedRequest { get; set; } = null!;

        /// <summary>
        /// Compartment OCID of the host
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

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("osInfo", required: true)]
        public Input<string> OsInfo { get; set; } = null!;

        public WlpAgentArgs()
        {
        }
        public static new WlpAgentArgs Empty => new WlpAgentArgs();
    }

    public sealed class WlpAgentState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The version of the agent making the request
        /// </summary>
        [Input("agentVersion")]
        public Input<string>? AgentVersion { get; set; }

        /// <summary>
        /// The certificate ID returned by Oracle Cloud Infrastructure certificates service
        /// </summary>
        [Input("certificateId")]
        public Input<string>? CertificateId { get; set; }

        /// <summary>
        /// (Updatable) The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key
        /// </summary>
        [Input("certificateSignedRequest")]
        public Input<string>? CertificateSignedRequest { get; set; }

        /// <summary>
        /// Compartment OCID of the host
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

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// 
        /// Avoid entering confidential information.
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// OCID for instance in which WlpAgent is installed
        /// </summary>
        [Input("hostId")]
        public Input<string>? HostId { get; set; }

        /// <summary>
        /// Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("osInfo")]
        public Input<string>? OsInfo { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// TenantId of the host
        /// </summary>
        [Input("tenantId")]
        public Input<string>? TenantId { get; set; }

        /// <summary>
        /// The date and time the WlpAgent was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the WlpAgent was updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public WlpAgentState()
        {
        }
        public static new WlpAgentState Empty => new WlpAgentState();
    }
}
