// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh
{
    /// <summary>
    /// This resource provides the Ingress Gateway resource in Oracle Cloud Infrastructure Service Mesh service.
    /// 
    /// Creates a new IngressGateway.
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
    ///     var testIngressGateway = new Oci.ServiceMesh.IngressGateway("testIngressGateway", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         Hosts = new[]
    ///         {
    ///             new Oci.ServiceMesh.Inputs.IngressGatewayHostArgs
    ///             {
    ///                 Listeners = new[]
    ///                 {
    ///                     new Oci.ServiceMesh.Inputs.IngressGatewayHostListenerArgs
    ///                     {
    ///                         Port = @var.Ingress_gateway_hosts_listeners_port,
    ///                         Protocol = @var.Ingress_gateway_hosts_listeners_protocol,
    ///                         Tls = new Oci.ServiceMesh.Inputs.IngressGatewayHostListenerTlsArgs
    ///                         {
    ///                             Mode = @var.Ingress_gateway_hosts_listeners_tls_mode,
    ///                             ClientValidation = new Oci.ServiceMesh.Inputs.IngressGatewayHostListenerTlsClientValidationArgs
    ///                             {
    ///                                 SubjectAlternateNames = @var.Ingress_gateway_hosts_listeners_tls_client_validation_subject_alternate_names,
    ///                                 TrustedCaBundle = new Oci.ServiceMesh.Inputs.IngressGatewayHostListenerTlsClientValidationTrustedCaBundleArgs
    ///                                 {
    ///                                     Type = @var.Ingress_gateway_hosts_listeners_tls_client_validation_trusted_ca_bundle_type,
    ///                                     CaBundleId = oci_certificates_management_ca_bundle.Test_ca_bundle.Id,
    ///                                     SecretName = oci_vault_secret.Test_secret.Name,
    ///                                 },
    ///                             },
    ///                             ServerCertificate = new Oci.ServiceMesh.Inputs.IngressGatewayHostListenerTlsServerCertificateArgs
    ///                             {
    ///                                 Type = @var.Ingress_gateway_hosts_listeners_tls_server_certificate_type,
    ///                                 CertificateId = oci_certificates_management_certificate.Test_certificate.Id,
    ///                                 SecretName = oci_vault_secret.Test_secret.Name,
    ///                             },
    ///                         },
    ///                     },
    ///                 },
    ///                 Name = @var.Ingress_gateway_hosts_name,
    ///                 Hostnames = @var.Ingress_gateway_hosts_hostnames,
    ///             },
    ///         },
    ///         MeshId = oci_service_mesh_mesh.Test_mesh.Id,
    ///         AccessLogging = new Oci.ServiceMesh.Inputs.IngressGatewayAccessLoggingArgs
    ///         {
    ///             IsEnabled = @var.Ingress_gateway_access_logging_is_enabled,
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = @var.Ingress_gateway_description,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         Mtls = new Oci.ServiceMesh.Inputs.IngressGatewayMtlsArgs
    ///         {
    ///             MaximumValidity = @var.Ingress_gateway_mtls_maximum_validity,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// IngressGateways can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:ServiceMesh/ingressGateway:IngressGateway test_ingress_gateway "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:ServiceMesh/ingressGateway:IngressGateway")]
    public partial class IngressGateway : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) This configuration determines if logging is enabled and where the logs will be output.
        /// </summary>
        [Output("accessLogging")]
        public Output<Outputs.IngressGatewayAccessLogging> AccessLogging { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An array of hostnames and their listener configuration that this gateway will bind to.
        /// </summary>
        [Output("hosts")]
        public Output<ImmutableArray<Outputs.IngressGatewayHost>> Hosts { get; private set; } = null!;

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the service mesh in which this ingress gateway is created.
        /// </summary>
        [Output("meshId")]
        public Output<string> MeshId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Mutual TLS settings used when sending requests to virtual services within the mesh.
        /// </summary>
        [Output("mtls")]
        public Output<Outputs.IngressGatewayMtls> Mtls { get; private set; } = null!;

        /// <summary>
        /// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The current state of the Resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when this resource was created in an RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when this resource was updated in an RFC3339 formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a IngressGateway resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IngressGateway(string name, IngressGatewayArgs args, CustomResourceOptions? options = null)
            : base("oci:ServiceMesh/ingressGateway:IngressGateway", name, args ?? new IngressGatewayArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IngressGateway(string name, Input<string> id, IngressGatewayState? state = null, CustomResourceOptions? options = null)
            : base("oci:ServiceMesh/ingressGateway:IngressGateway", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing IngressGateway resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IngressGateway Get(string name, Input<string> id, IngressGatewayState? state = null, CustomResourceOptions? options = null)
        {
            return new IngressGateway(name, id, state, options);
        }
    }

    public sealed class IngressGatewayArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) This configuration determines if logging is enabled and where the logs will be output.
        /// </summary>
        [Input("accessLogging")]
        public Input<Inputs.IngressGatewayAccessLoggingArgs>? AccessLogging { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("hosts", required: true)]
        private InputList<Inputs.IngressGatewayHostArgs>? _hosts;

        /// <summary>
        /// (Updatable) An array of hostnames and their listener configuration that this gateway will bind to.
        /// </summary>
        public InputList<Inputs.IngressGatewayHostArgs> Hosts
        {
            get => _hosts ?? (_hosts = new InputList<Inputs.IngressGatewayHostArgs>());
            set => _hosts = value;
        }

        /// <summary>
        /// The OCID of the service mesh in which this ingress gateway is created.
        /// </summary>
        [Input("meshId", required: true)]
        public Input<string> MeshId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Mutual TLS settings used when sending requests to virtual services within the mesh.
        /// </summary>
        [Input("mtls")]
        public Input<Inputs.IngressGatewayMtlsArgs>? Mtls { get; set; }

        /// <summary>
        /// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public IngressGatewayArgs()
        {
        }
        public static new IngressGatewayArgs Empty => new IngressGatewayArgs();
    }

    public sealed class IngressGatewayState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) This configuration determines if logging is enabled and where the logs will be output.
        /// </summary>
        [Input("accessLogging")]
        public Input<Inputs.IngressGatewayAccessLoggingGetArgs>? AccessLogging { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("hosts")]
        private InputList<Inputs.IngressGatewayHostGetArgs>? _hosts;

        /// <summary>
        /// (Updatable) An array of hostnames and their listener configuration that this gateway will bind to.
        /// </summary>
        public InputList<Inputs.IngressGatewayHostGetArgs> Hosts
        {
            get => _hosts ?? (_hosts = new InputList<Inputs.IngressGatewayHostGetArgs>());
            set => _hosts = value;
        }

        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the service mesh in which this ingress gateway is created.
        /// </summary>
        [Input("meshId")]
        public Input<string>? MeshId { get; set; }

        /// <summary>
        /// (Updatable) Mutual TLS settings used when sending requests to virtual services within the mesh.
        /// </summary>
        [Input("mtls")]
        public Input<Inputs.IngressGatewayMtlsGetArgs>? Mtls { get; set; }

        /// <summary>
        /// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The current state of the Resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time when this resource was created in an RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when this resource was updated in an RFC3339 formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public IngressGatewayState()
        {
        }
        public static new IngressGatewayState Empty => new IngressGatewayState();
    }
}