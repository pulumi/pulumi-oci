// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ContainerInstanceContainerHealthCheckGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("commands")]
        private InputList<string>? _commands;

        /// <summary>
        /// The list of strings which will be concatenated to a single command for checking container's status.
        /// </summary>
        public InputList<string> Commands
        {
            get => _commands ?? (_commands = new InputList<string>());
            set => _commands = value;
        }

        /// <summary>
        /// The action will be triggered when the container health check fails. There are two types of action: KILL or NONE. The default action is KILL. If failure action is KILL, the container will be subject to the container restart policy.
        /// </summary>
        [Input("failureAction")]
        public Input<string>? FailureAction { get; set; }

        /// <summary>
        /// Number of consecutive failures at which we consider the check failed.
        /// </summary>
        [Input("failureThreshold")]
        public Input<int>? FailureThreshold { get; set; }

        [Input("headers")]
        private InputList<Inputs.ContainerInstanceContainerHealthCheckHeaderGetArgs>? _headers;

        /// <summary>
        /// Container health check Http's headers.
        /// </summary>
        public InputList<Inputs.ContainerInstanceContainerHealthCheckHeaderGetArgs> Headers
        {
            get => _headers ?? (_headers = new InputList<Inputs.ContainerInstanceContainerHealthCheckHeaderGetArgs>());
            set => _headers = value;
        }

        /// <summary>
        /// Container health check type.
        /// </summary>
        [Input("healthCheckType", required: true)]
        public Input<string> HealthCheckType { get; set; } = null!;

        /// <summary>
        /// The initial delay in seconds before start checking container health status.
        /// </summary>
        [Input("initialDelayInSeconds")]
        public Input<int>? InitialDelayInSeconds { get; set; }

        /// <summary>
        /// Number of seconds between two consecutive runs for checking container health.
        /// </summary>
        [Input("intervalInSeconds")]
        public Input<int>? IntervalInSeconds { get; set; }

        /// <summary>
        /// The name of the volume. This has be unique cross single ContainerInstance.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Optional) Relative path for this file inside the volume mount directory. By default, the file is presented at the root of the volume mount path.
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        /// <summary>
        /// Container health check Http's port.
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("statusDetails")]
        public Input<string>? StatusDetails { get; set; }

        /// <summary>
        /// Number of consecutive successes at which we consider the check succeeded again after it was in failure state.
        /// </summary>
        [Input("successThreshold")]
        public Input<int>? SuccessThreshold { get; set; }

        /// <summary>
        /// Length of waiting time in seconds before marking health check failed.
        /// </summary>
        [Input("timeoutInSeconds")]
        public Input<int>? TimeoutInSeconds { get; set; }

        public ContainerInstanceContainerHealthCheckGetArgs()
        {
        }
        public static new ContainerInstanceContainerHealthCheckGetArgs Empty => new ContainerInstanceContainerHealthCheckGetArgs();
    }
}