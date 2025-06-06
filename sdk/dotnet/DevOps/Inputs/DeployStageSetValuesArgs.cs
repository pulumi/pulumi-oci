// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployStageSetValuesArgs : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeployStageSetValuesItemArgs>? _items;

        /// <summary>
        /// (Updatable) List of parameters defined to set helm value.
        /// </summary>
        public InputList<Inputs.DeployStageSetValuesItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeployStageSetValuesItemArgs>());
            set => _items = value;
        }

        public DeployStageSetValuesArgs()
        {
        }
        public static new DeployStageSetValuesArgs Empty => new DeployStageSetValuesArgs();
    }
}
