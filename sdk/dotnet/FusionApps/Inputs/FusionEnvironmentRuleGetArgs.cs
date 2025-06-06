// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FusionApps.Inputs
{

    public sealed class FusionEnvironmentRuleGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Rule type
        /// </summary>
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        [Input("conditions", required: true)]
        private InputList<Inputs.FusionEnvironmentRuleConditionGetArgs>? _conditions;

        /// <summary>
        /// (Updatable)
        /// </summary>
        public InputList<Inputs.FusionEnvironmentRuleConditionGetArgs> Conditions
        {
            get => _conditions ?? (_conditions = new InputList<Inputs.FusionEnvironmentRuleConditionGetArgs>());
            set => _conditions = value;
        }

        /// <summary>
        /// (Updatable) A brief description of the access control rule. Avoid entering confidential information. example: `192.168.0.0/16 and 2001:db8::/32 are trusted clients. Whitelist them.` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        public FusionEnvironmentRuleGetArgs()
        {
        }
        public static new FusionEnvironmentRuleGetArgs Empty => new FusionEnvironmentRuleGetArgs();
    }
}
