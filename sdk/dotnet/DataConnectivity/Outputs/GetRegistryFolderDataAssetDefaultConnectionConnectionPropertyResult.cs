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
    public sealed class GetRegistryFolderDataAssetDefaultConnectionConnectionPropertyResult
    {
        /// <summary>
        /// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The value for the connection name property.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetRegistryFolderDataAssetDefaultConnectionConnectionPropertyResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}