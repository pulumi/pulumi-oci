// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedInstanceModuleStreamsModuleStreamOnManagedInstanceResult
    {
        /// <summary>
        /// The name of a module.  This parameter is required if a streamName is specified.
        /// </summary>
        public readonly string ModuleName;
        /// <summary>
        /// The set of profiles that the module stream contains.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstanceModuleStreamsModuleStreamOnManagedInstanceProfileResult> Profiles;
        /// <summary>
        /// The OCID of the software source that provides this module stream.
        /// </summary>
        public readonly string SoftwareSourceId;
        /// <summary>
        /// The status of the stream
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The name of the stream of the containing module.  This parameter is required if a profileName is specified.
        /// </summary>
        public readonly string StreamName;
        /// <summary>
        /// The date and time of the last status change for this profile, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeModified;

        [OutputConstructor]
        private GetManagedInstanceModuleStreamsModuleStreamOnManagedInstanceResult(
            string moduleName,

            ImmutableArray<Outputs.GetManagedInstanceModuleStreamsModuleStreamOnManagedInstanceProfileResult> profiles,

            string softwareSourceId,

            string status,

            string streamName,

            string timeModified)
        {
            ModuleName = moduleName;
            Profiles = profiles;
            SoftwareSourceId = softwareSourceId;
            Status = status;
            StreamName = streamName;
            TimeModified = timeModified;
        }
    }
}
