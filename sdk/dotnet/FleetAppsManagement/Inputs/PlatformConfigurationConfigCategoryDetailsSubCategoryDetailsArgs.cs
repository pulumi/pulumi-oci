// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsArgs : global::Pulumi.ResourceArgs
    {
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

        [Input("credentials")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsCredentialArgs>? _credentials;

        /// <summary>
        /// (Updatable) OCID for the Credential name to be associated with the Product Stack. These are useful for target discovery or lifecycle management activities, for example, Oracle WebLogic admin credentials for Oracle WebLogic Application server.
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsCredentialArgs> Credentials
        {
            get => _credentials ?? (_credentials = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsCredentialArgs>());
            set => _credentials = value;
        }

        [Input("patchTypes")]
        private InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsPatchTypeArgs>? _patchTypes;

        /// <summary>
        /// (Updatable) Patch Types associated with this Product Stack which will be considered as Product.
        /// </summary>
        public InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsPatchTypeArgs> PatchTypes
        {
            get => _patchTypes ?? (_patchTypes = new InputList<Inputs.PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsPatchTypeArgs>());
            set => _patchTypes = value;
        }

        /// <summary>
        /// (Updatable) SubCategory of Product Stack.
        /// </summary>
        [Input("subCategory", required: true)]
        public Input<string> SubCategory { get; set; } = null!;

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

        public PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsArgs()
        {
        }
        public static new PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsArgs Empty => new PlatformConfigurationConfigCategoryDetailsSubCategoryDetailsArgs();
    }
}
