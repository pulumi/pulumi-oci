// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class PlatformConfigurationConfigCategoryDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("compatibleProducts")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCompatibleProductGetArgs>? _compatibleProducts;

        /// <summary>
        /// (Updatable) Products compatible with this Product. Provide products from the list of other products you have created that are compatible with the present one
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCompatibleProductGetArgs> CompatibleProducts
        {
            get => _compatibleProducts ?? (_compatibleProducts = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCompatibleProductGetArgs>());
            set => _compatibleProducts = value;
        }

        [Input("components")]
        private InputList<string>? _components;

        /// <summary>
        /// (Updatable) Various components of the Product. For example:The administration server or node manager can be the components of the Oracle WebLogic Application server. Forms server or concurrent manager can be the components of the Oracle E-Business Suite.
        /// </summary>
        public InputList<string> Components
        {
            get => _components ?? (_components = new InputList<string>());
            set => _components = value;
        }

        /// <summary>
        /// (Updatable) Category of configuration
        /// </summary>
        [Input("configCategory", required: true)]
        public Input<string> ConfigCategory { get; set; } = null!;

        [Input("credentials")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCredentialGetArgs>? _credentials;

        /// <summary>
        /// (Updatable) OCID for the Credential name to be associated with the Product. These are useful for target discovery or lifecycle management activities, for example, Oracle WebLogic admin credentials for Oracle WebLogic Application server.
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCredentialGetArgs> Credentials
        {
            get => _credentials ?? (_credentials = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsCredentialGetArgs>());
            set => _credentials = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the resource.
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        [Input("instanceName")]
        public Input<string>? InstanceName { get; set; }

        [Input("patchTypes")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsPatchTypeGetArgs>? _patchTypes;

        /// <summary>
        /// (Updatable) Patch Types associated with this Product.
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsPatchTypeGetArgs> PatchTypes
        {
            get => _patchTypes ?? (_patchTypes = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsPatchTypeGetArgs>());
            set => _patchTypes = value;
        }

        [Input("products")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsProductGetArgs>? _products;

        /// <summary>
        /// (Updatable) Products that belong to the stack. For example, Oracle WebLogic and Java for the Oracle Fusion Middleware product stack.
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsProductGetArgs> Products
        {
            get => _products ?? (_products = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsProductGetArgs>());
            set => _products = value;
        }

        /// <summary>
        /// (Updatable) ProductStack Config Category Details.
        /// </summary>
        [Input("subCategoryDetails")]
        public Input<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsGetArgs>? SubCategoryDetails { get; set; }

        [Input("versions")]
        private InputList<string>? _versions;

        /// <summary>
        /// (Updatable) Versions associated with the PRODUCT .
        /// </summary>
        public InputList<string> Versions
        {
            get => _versions ?? (_versions = new InputList<string>());
            set => _versions = value;
        }

        public PlatformConfigurationConfigCategoryDetailsGetArgs()
        {
        }
        public static new PlatformConfigurationConfigCategoryDetailsGetArgs Empty => new PlatformConfigurationConfigCategoryDetailsGetArgs();
    }
}
