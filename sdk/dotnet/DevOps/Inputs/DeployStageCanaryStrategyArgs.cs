// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployStageCanaryStrategyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of the Ingress resource.
        /// </summary>
        [Input("ingressName", required: true)]
        public Input<string> IngressName { get; set; } = null!;

        /// <summary>
        /// (Updatable) Default namespace to be used for Kubernetes deployment when not specified in the manifest.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// Canary strategy type
        /// </summary>
        [Input("strategyType", required: true)]
        public Input<string> StrategyType { get; set; } = null!;

        public DeployStageCanaryStrategyArgs()
        {
        }
        public static new DeployStageCanaryStrategyArgs Empty => new DeployStageCanaryStrategyArgs();
    }
}