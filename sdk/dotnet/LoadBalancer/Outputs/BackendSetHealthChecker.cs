// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class BackendSetHealthChecker
    {
        /// <summary>
        /// (Updatable) The interval between health checks, in milliseconds.  Example: `10000`
        /// </summary>
        public readonly int? IntervalMs;
        /// <summary>
        /// (Updatable) The backend server port against which to run the health check. If the port is not specified, the load balancer uses the port information from the `Backend` object.  Example: `8080`
        /// </summary>
        public readonly int? Port;
        /// <summary>
        /// (Updatable) The protocol the health check must use; either HTTP or TCP.  Example: `HTTP`
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// (Updatable) A regular expression for parsing the response body from the backend server.  Example: `^((?!false).|\s)*$`
        /// </summary>
        public readonly string? ResponseBodyRegex;
        /// <summary>
        /// (Updatable) The number of retries to attempt before a backend server is considered "unhealthy". This number also applies when recovering a server to the "healthy" state.  Example: `3`
        /// </summary>
        public readonly int? Retries;
        /// <summary>
        /// (Updatable) The status code a healthy backend server should return.  Example: `200`
        /// </summary>
        public readonly int? ReturnCode;
        /// <summary>
        /// (Updatable) The maximum time, in milliseconds, to wait for a reply to a health check. A health check is successful only if a reply returns within this timeout period.  Example: `3000`
        /// </summary>
        public readonly int? TimeoutInMillis;
        /// <summary>
        /// (Updatable) The path against which to run the health check.  Example: `/healthcheck`
        /// </summary>
        public readonly string? UrlPath;

        [OutputConstructor]
        private BackendSetHealthChecker(
            int? intervalMs,

            int? port,

            string protocol,

            string? responseBodyRegex,

            int? retries,

            int? returnCode,

            int? timeoutInMillis,

            string? urlPath)
        {
            IntervalMs = intervalMs;
            Port = port;
            Protocol = protocol;
            ResponseBodyRegex = responseBodyRegex;
            Retries = retries;
            ReturnCode = returnCode;
            TimeoutInMillis = timeoutInMillis;
            UrlPath = urlPath;
        }
    }
}