// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity.Outputs
{

    [OutputType]
    public sealed class RegistryFolderDataAssetNativeTypeSystemTypeConfigDefinitionParentRef
    {
        /// <summary>
        /// (Updatable) Key of the parent object.
        /// </summary>
        public readonly string? Parent;

        [OutputConstructor]
        private RegistryFolderDataAssetNativeTypeSystemTypeConfigDefinitionParentRef(string? parent)
        {
            Parent = parent;
        }
    }
}