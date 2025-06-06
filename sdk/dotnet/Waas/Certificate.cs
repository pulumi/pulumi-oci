// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas
{
    /// <summary>
    /// This resource provides the Certificate resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
    /// 
    /// Allows an SSL certificate to be added to a WAAS policy. The Web Application Firewall terminates SSL connections to inspect requests in runtime, and then re-encrypts requests before sending them to the origin for fulfillment.
    /// 
    /// For more information, see [WAF Settings](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/wafsettings.htm).
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
    ///     var testCertificate = new Oci.Waas.Certificate("test_certificate", new()
    ///     {
    ///         CertificateData = certificateCertificateData,
    ///         CompartmentId = compartmentId,
    ///         PrivateKeyData = certificatePrivateKeyData,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         DisplayName = certificateDisplayName,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         IsTrustVerificationDisabled = certificateIsTrustVerificationDisabled,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Waas/certificate:Certificate")]
    public partial class Certificate : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The data of the SSL certificate.
        /// 
        /// **Note:** Many SSL certificate providers require an intermediate certificate chain to ensure a trusted status. If your SSL certificate requires an intermediate certificate chain, please append the intermediate certificate key in the `certificateData` field after the leaf certificate issued by the SSL certificate provider. If you are unsure if your certificate requires an intermediate certificate chain, see your certificate provider's documentation.
        /// 
        /// The example below shows an intermediate certificate appended to a leaf certificate.
        /// </summary>
        [Output("certificateData")]
        public Output<string> CertificateData { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Additional attributes associated with users or public keys for managing relationships between Certificate Authorities.
        /// </summary>
        [Output("extensions")]
        public Output<ImmutableArray<Outputs.CertificateExtension>> Extensions { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Set to `true` if the SSL certificate is self-signed.
        /// </summary>
        [Output("isTrustVerificationDisabled")]
        public Output<bool> IsTrustVerificationDisabled { get; private set; } = null!;

        [Output("issuedBy")]
        public Output<string> IssuedBy { get; private set; } = null!;

        /// <summary>
        /// The issuer of the certificate.
        /// </summary>
        [Output("issuerNames")]
        public Output<ImmutableArray<Outputs.CertificateIssuerName>> IssuerNames { get; private set; } = null!;

        /// <summary>
        /// The private key of the SSL certificate.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("privateKeyData")]
        public Output<string> PrivateKeyData { get; private set; } = null!;

        /// <summary>
        /// Information about the public key and the algorithm used by the public key.
        /// </summary>
        [Output("publicKeyInfos")]
        public Output<ImmutableArray<Outputs.CertificatePublicKeyInfo>> PublicKeyInfos { get; private set; } = null!;

        /// <summary>
        /// A unique, positive integer assigned by the Certificate Authority (CA). The issuer name and serial number identify a unique certificate.
        /// </summary>
        [Output("serialNumber")]
        public Output<string> SerialNumber { get; private set; } = null!;

        /// <summary>
        /// The identifier for the cryptographic algorithm used by the Certificate Authority (CA) to sign this certificate.
        /// </summary>
        [Output("signatureAlgorithm")]
        public Output<string> SignatureAlgorithm { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the SSL certificate.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The entity to be secured by the certificate.
        /// </summary>
        [Output("subjectNames")]
        public Output<ImmutableArray<Outputs.CertificateSubjectName>> SubjectNames { get; private set; } = null!;

        /// <summary>
        /// The date and time the certificate was created, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the certificate will expire, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Output("timeNotValidAfter")]
        public Output<string> TimeNotValidAfter { get; private set; } = null!;

        /// <summary>
        /// The date and time the certificate will become valid, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Output("timeNotValidBefore")]
        public Output<string> TimeNotValidBefore { get; private set; } = null!;

        /// <summary>
        /// The version of the encoded certificate.
        /// </summary>
        [Output("version")]
        public Output<int> Version { get; private set; } = null!;


        /// <summary>
        /// Create a Certificate resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Certificate(string name, CertificateArgs args, CustomResourceOptions? options = null)
            : base("oci:Waas/certificate:Certificate", name, args ?? new CertificateArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Certificate(string name, Input<string> id, CertificateState? state = null, CustomResourceOptions? options = null)
            : base("oci:Waas/certificate:Certificate", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
                AdditionalSecretOutputs =
                {
                    "privateKeyData",
                },
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Certificate resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Certificate Get(string name, Input<string> id, CertificateState? state = null, CustomResourceOptions? options = null)
        {
            return new Certificate(name, id, state, options);
        }
    }

    public sealed class CertificateArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The data of the SSL certificate.
        /// 
        /// **Note:** Many SSL certificate providers require an intermediate certificate chain to ensure a trusted status. If your SSL certificate requires an intermediate certificate chain, please append the intermediate certificate key in the `certificateData` field after the leaf certificate issued by the SSL certificate provider. If you are unsure if your certificate requires an intermediate certificate chain, see your certificate provider's documentation.
        /// 
        /// The example below shows an intermediate certificate appended to a leaf certificate.
        /// </summary>
        [Input("certificateData", required: true)]
        public Input<string> CertificateData { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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
        /// Set to `true` if the SSL certificate is self-signed.
        /// </summary>
        [Input("isTrustVerificationDisabled")]
        public Input<bool>? IsTrustVerificationDisabled { get; set; }

        [Input("privateKeyData", required: true)]
        private Input<string>? _privateKeyData;

        /// <summary>
        /// The private key of the SSL certificate.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public Input<string>? PrivateKeyData
        {
            get => _privateKeyData;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _privateKeyData = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        public CertificateArgs()
        {
        }
        public static new CertificateArgs Empty => new CertificateArgs();
    }

    public sealed class CertificateState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The data of the SSL certificate.
        /// 
        /// **Note:** Many SSL certificate providers require an intermediate certificate chain to ensure a trusted status. If your SSL certificate requires an intermediate certificate chain, please append the intermediate certificate key in the `certificateData` field after the leaf certificate issued by the SSL certificate provider. If you are unsure if your certificate requires an intermediate certificate chain, see your certificate provider's documentation.
        /// 
        /// The example below shows an intermediate certificate appended to a leaf certificate.
        /// </summary>
        [Input("certificateData")]
        public Input<string>? CertificateData { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to create the SSL certificate.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name for the SSL certificate. The name can be changed and does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("extensions")]
        private InputList<Inputs.CertificateExtensionGetArgs>? _extensions;

        /// <summary>
        /// Additional attributes associated with users or public keys for managing relationships between Certificate Authorities.
        /// </summary>
        public InputList<Inputs.CertificateExtensionGetArgs> Extensions
        {
            get => _extensions ?? (_extensions = new InputList<Inputs.CertificateExtensionGetArgs>());
            set => _extensions = value;
        }

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
        /// Set to `true` if the SSL certificate is self-signed.
        /// </summary>
        [Input("isTrustVerificationDisabled")]
        public Input<bool>? IsTrustVerificationDisabled { get; set; }

        [Input("issuedBy")]
        public Input<string>? IssuedBy { get; set; }

        [Input("issuerNames")]
        private InputList<Inputs.CertificateIssuerNameGetArgs>? _issuerNames;

        /// <summary>
        /// The issuer of the certificate.
        /// </summary>
        public InputList<Inputs.CertificateIssuerNameGetArgs> IssuerNames
        {
            get => _issuerNames ?? (_issuerNames = new InputList<Inputs.CertificateIssuerNameGetArgs>());
            set => _issuerNames = value;
        }

        [Input("privateKeyData")]
        private Input<string>? _privateKeyData;

        /// <summary>
        /// The private key of the SSL certificate.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public Input<string>? PrivateKeyData
        {
            get => _privateKeyData;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _privateKeyData = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        [Input("publicKeyInfos")]
        private InputList<Inputs.CertificatePublicKeyInfoGetArgs>? _publicKeyInfos;

        /// <summary>
        /// Information about the public key and the algorithm used by the public key.
        /// </summary>
        public InputList<Inputs.CertificatePublicKeyInfoGetArgs> PublicKeyInfos
        {
            get => _publicKeyInfos ?? (_publicKeyInfos = new InputList<Inputs.CertificatePublicKeyInfoGetArgs>());
            set => _publicKeyInfos = value;
        }

        /// <summary>
        /// A unique, positive integer assigned by the Certificate Authority (CA). The issuer name and serial number identify a unique certificate.
        /// </summary>
        [Input("serialNumber")]
        public Input<string>? SerialNumber { get; set; }

        /// <summary>
        /// The identifier for the cryptographic algorithm used by the Certificate Authority (CA) to sign this certificate.
        /// </summary>
        [Input("signatureAlgorithm")]
        public Input<string>? SignatureAlgorithm { get; set; }

        /// <summary>
        /// The current lifecycle state of the SSL certificate.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("subjectNames")]
        private InputList<Inputs.CertificateSubjectNameGetArgs>? _subjectNames;

        /// <summary>
        /// The entity to be secured by the certificate.
        /// </summary>
        public InputList<Inputs.CertificateSubjectNameGetArgs> SubjectNames
        {
            get => _subjectNames ?? (_subjectNames = new InputList<Inputs.CertificateSubjectNameGetArgs>());
            set => _subjectNames = value;
        }

        /// <summary>
        /// The date and time the certificate was created, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the certificate will expire, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeNotValidAfter")]
        public Input<string>? TimeNotValidAfter { get; set; }

        /// <summary>
        /// The date and time the certificate will become valid, expressed in RFC 3339 timestamp format.
        /// </summary>
        [Input("timeNotValidBefore")]
        public Input<string>? TimeNotValidBefore { get; set; }

        /// <summary>
        /// The version of the encoded certificate.
        /// </summary>
        [Input("version")]
        public Input<int>? Version { get; set; }

        public CertificateState()
        {
        }
        public static new CertificateState Empty => new CertificateState();
    }
}
