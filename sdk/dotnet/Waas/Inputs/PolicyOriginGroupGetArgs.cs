// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class PolicyOriginGroupGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("label", required: true)]
        public Input<string> Label { get; set; } = null!;

        [Input("originGroups", required: true)]
        private InputList<Inputs.PolicyOriginGroupOriginGroupGetArgs>? _originGroups;
        public InputList<Inputs.PolicyOriginGroupOriginGroupGetArgs> OriginGroups
        {
            get => _originGroups ?? (_originGroups = new InputList<Inputs.PolicyOriginGroupOriginGroupGetArgs>());
            set => _originGroups = value;
        }

        public PolicyOriginGroupGetArgs()
        {
        }
        public static new PolicyOriginGroupGetArgs Empty => new PolicyOriginGroupGetArgs();
    }
}
