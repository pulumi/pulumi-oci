// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class DataMaskRuleTargetSelectedArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Target selection.
        /// </summary>
        [Input("kind", required: true)]
        public Input<string> Kind { get; set; } = null!;

        [Input("values")]
        private InputList<string>? _values;

        /// <summary>
        /// (Updatable) Types of Targets
        /// </summary>
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public DataMaskRuleTargetSelectedArgs()
        {
        }
        public static new DataMaskRuleTargetSelectedArgs Empty => new DataMaskRuleTargetSelectedArgs();
    }
}