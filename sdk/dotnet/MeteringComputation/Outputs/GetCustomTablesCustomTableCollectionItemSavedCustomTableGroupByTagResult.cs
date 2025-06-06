// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Outputs
{

    [OutputType]
    public sealed class GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTagResult
    {
        /// <summary>
        /// The tag key.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The tag namespace.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The tag value.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTagResult(
            string key,

            string @namespace,

            string value)
        {
            Key = key;
            Namespace = @namespace;
            Value = value;
        }
    }
}
