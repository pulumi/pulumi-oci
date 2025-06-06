// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class DiscoveryJobsResultModifiedAttributeGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("appDefinedChildColumnKeys")]
        private InputList<string>? _appDefinedChildColumnKeys;

        /// <summary>
        /// Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
        /// </summary>
        public InputList<string> AppDefinedChildColumnKeys
        {
            get => _appDefinedChildColumnKeys ?? (_appDefinedChildColumnKeys = new InputList<string>());
            set => _appDefinedChildColumnKeys = value;
        }

        [Input("dbDefinedChildColumnKeys")]
        private InputList<string>? _dbDefinedChildColumnKeys;

        /// <summary>
        /// Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
        /// </summary>
        public InputList<string> DbDefinedChildColumnKeys
        {
            get => _dbDefinedChildColumnKeys ?? (_dbDefinedChildColumnKeys = new InputList<string>());
            set => _dbDefinedChildColumnKeys = value;
        }

        public DiscoveryJobsResultModifiedAttributeGetArgs()
        {
        }
        public static new DiscoveryJobsResultModifiedAttributeGetArgs Empty => new DiscoveryJobsResultModifiedAttributeGetArgs();
    }
}
