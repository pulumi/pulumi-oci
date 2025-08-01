// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Nosql
{
    /// <summary>
    /// This resource provides the Configuration in Oracle Cloud Infrastructure NoSQL Database service.
    /// 
    /// Updates the service-level configuration.  The discriminator value
    /// `UpdateConfigurationDetails.environment` must match the service's
    /// environment type.
    /// 
    /// A configuration serves as a centralized repository for global parameters that
    /// affect the NoSQL service. Currently, there is only one such parameter: a
    /// customer-provided key for encrypting NoSQL data at rest.
    /// 
    /// The Customer-Managed Encryption Keys (CMEK) feature is exclusively available
    /// in private NoSQL environments dedicated to a single tenancy, where the CMEK
    /// option has been enabled. Updating the configuration of the default, regional,
    /// multi-tenancy NoSQL service is not supported.
    /// 
    /// To specify the dedicated environment, set the environment variable
    /// CLIENT_HOST_OVERRIDES=oci_nosql.NosqlClient=$ENDPOINT
    /// Where $ENDPOINT is the endpoint of the dedicated NoSQL environment.
    /// For example:
    /// $ export CLIENT_HOST_OVERRIDES=oci_nosql.NosqlClient=https://acme-widgets.nosql.oci.oraclecloud.com
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
    ///     var testConfiguration = new Oci.Nosql.Configuration("test_configuration", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         Environment = "HOSTED",
    ///         IsOpcDryRun = configurationIsOpcDryRun,
    ///         KmsKey = new Oci.Nosql.Inputs.ConfigurationKmsKeyArgs
    ///         {
    ///             Id = configurationKmsKeyId,
    ///             KmsVaultId = testVault.Id,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Configurations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Nosql/configuration:Configuration test_configuration "configuration/compartmentId/{compartmentId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Nosql/configuration:Configuration")]
    public partial class Configuration : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The tenancy's OCID
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The service environment type.
        /// </summary>
        [Output("environment")]
        public Output<string> Environment { get; private set; } = null!;

        /// <summary>
        /// (Updatable) If true, indicates that the request is a dry run. A dry run request does not modify the configuration item details and is used only to perform validation on the submitted data.
        /// </summary>
        [Output("isOpcDryRun")]
        public Output<bool> IsOpcDryRun { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Information about the state of the service's encryption key management. The following properties are read-only and ignored when this object is used in UpdateConfiguration: kmsKeyState, timeCreated, timeUpdated.
        /// </summary>
        [Output("kmsKey")]
        public Output<Outputs.ConfigurationKmsKey> KmsKey { get; private set; } = null!;


        /// <summary>
        /// Create a Configuration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Configuration(string name, ConfigurationArgs args, CustomResourceOptions? options = null)
            : base("oci:Nosql/configuration:Configuration", name, args ?? new ConfigurationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Configuration(string name, Input<string> id, ConfigurationState? state = null, CustomResourceOptions? options = null)
            : base("oci:Nosql/configuration:Configuration", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Configuration resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Configuration Get(string name, Input<string> id, ConfigurationState? state = null, CustomResourceOptions? options = null)
        {
            return new Configuration(name, id, state, options);
        }
    }

    public sealed class ConfigurationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The tenancy's OCID
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The service environment type.
        /// </summary>
        [Input("environment", required: true)]
        public Input<string> Environment { get; set; } = null!;

        /// <summary>
        /// (Updatable) If true, indicates that the request is a dry run. A dry run request does not modify the configuration item details and is used only to perform validation on the submitted data.
        /// </summary>
        [Input("isOpcDryRun")]
        public Input<bool>? IsOpcDryRun { get; set; }

        /// <summary>
        /// (Updatable) Information about the state of the service's encryption key management. The following properties are read-only and ignored when this object is used in UpdateConfiguration: kmsKeyState, timeCreated, timeUpdated.
        /// </summary>
        [Input("kmsKey")]
        public Input<Inputs.ConfigurationKmsKeyArgs>? KmsKey { get; set; }

        public ConfigurationArgs()
        {
        }
        public static new ConfigurationArgs Empty => new ConfigurationArgs();
    }

    public sealed class ConfigurationState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The tenancy's OCID
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The service environment type.
        /// </summary>
        [Input("environment")]
        public Input<string>? Environment { get; set; }

        /// <summary>
        /// (Updatable) If true, indicates that the request is a dry run. A dry run request does not modify the configuration item details and is used only to perform validation on the submitted data.
        /// </summary>
        [Input("isOpcDryRun")]
        public Input<bool>? IsOpcDryRun { get; set; }

        /// <summary>
        /// (Updatable) Information about the state of the service's encryption key management. The following properties are read-only and ignored when this object is used in UpdateConfiguration: kmsKeyState, timeCreated, timeUpdated.
        /// </summary>
        [Input("kmsKey")]
        public Input<Inputs.ConfigurationKmsKeyGetArgs>? KmsKey { get; set; }

        public ConfigurationState()
        {
        }
        public static new ConfigurationState Empty => new ConfigurationState();
    }
}
