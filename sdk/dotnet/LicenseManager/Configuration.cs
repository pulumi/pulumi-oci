// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LicenseManager
{
    /// <summary>
    /// This resource provides the Configuration resource in Oracle Cloud Infrastructure License Manager service.
    /// 
    /// Updates the configuration for the compartment.
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
    ///     var testConfiguration = new Oci.LicenseManager.Configuration("testConfiguration", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         EmailIds = @var.Configuration_email_ids,
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
    ///  $ pulumi import oci:LicenseManager/configuration:Configuration test_configuration "configuration/compartmentId/{compartmentId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LicenseManager/configuration:Configuration")]
    public partial class Configuration : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of email IDs associated with the configuration.
        /// </summary>
        [Output("emailIds")]
        public Output<ImmutableArray<string>> EmailIds { get; private set; } = null!;

        /// <summary>
        /// The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a Configuration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Configuration(string name, ConfigurationArgs args, CustomResourceOptions? options = null)
            : base("oci:LicenseManager/configuration:Configuration", name, args ?? new ConfigurationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Configuration(string name, Input<string> id, ConfigurationState? state = null, CustomResourceOptions? options = null)
            : base("oci:LicenseManager/configuration:Configuration", name, state, MakeResourceOptions(options, id))
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
        /// (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("emailIds", required: true)]
        private InputList<string>? _emailIds;

        /// <summary>
        /// (Updatable) List of email IDs associated with the configuration.
        /// </summary>
        public InputList<string> EmailIds
        {
            get => _emailIds ?? (_emailIds = new InputList<string>());
            set => _emailIds = value;
        }

        public ConfigurationArgs()
        {
        }
        public static new ConfigurationArgs Empty => new ConfigurationArgs();
    }

    public sealed class ConfigurationState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("emailIds")]
        private InputList<string>? _emailIds;

        /// <summary>
        /// (Updatable) List of email IDs associated with the configuration.
        /// </summary>
        public InputList<string> EmailIds
        {
            get => _emailIds ?? (_emailIds = new InputList<string>());
            set => _emailIds = value;
        }

        /// <summary>
        /// The time the configuration was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the configuration was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ConfigurationState()
        {
        }
        public static new ConfigurationState Empty => new ConfigurationState();
    }
}