// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class ExternalDbSystemDiscoveryPatchOperation
    {
        /// <summary>
        /// (Updatable) The operation can be one of these values: `MERGE`
        /// </summary>
        public readonly string Operation;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly string Selection;
        /// <summary>
        /// (Updatable) 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly Outputs.ExternalDbSystemDiscoveryPatchOperationValue? Value;

        [OutputConstructor]
        private ExternalDbSystemDiscoveryPatchOperation(
            string operation,

            string selection,

            Outputs.ExternalDbSystemDiscoveryPatchOperationValue? value)
        {
            Operation = operation;
            Selection = selection;
            Value = value;
        }
    }
}
