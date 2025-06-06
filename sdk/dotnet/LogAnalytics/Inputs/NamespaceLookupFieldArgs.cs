// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Inputs
{

    public sealed class NamespaceLookupFieldArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The common field name.
        /// </summary>
        [Input("commonFieldName")]
        public Input<string>? CommonFieldName { get; set; }

        /// <summary>
        /// (Updatable) The default match value.
        /// </summary>
        [Input("defaultMatchValue")]
        public Input<string>? DefaultMatchValue { get; set; }

        /// <summary>
        /// (Updatable) The display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) A flag indicating whether or not the field is a common field.
        /// </summary>
        [Input("isCommonField")]
        public Input<bool>? IsCommonField { get; set; }

        /// <summary>
        /// (Updatable) The match operator.
        /// </summary>
        [Input("matchOperator")]
        public Input<string>? MatchOperator { get; set; }

        /// <summary>
        /// (Updatable) The field name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The position.
        /// </summary>
        [Input("position")]
        public Input<string>? Position { get; set; }

        public NamespaceLookupFieldArgs()
        {
        }
        public static new NamespaceLookupFieldArgs Empty => new NamespaceLookupFieldArgs();
    }
}
