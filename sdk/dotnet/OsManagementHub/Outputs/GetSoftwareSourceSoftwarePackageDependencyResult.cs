// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetSoftwareSourceSoftwarePackageDependencyResult
    {
        /// <summary>
        /// The software package's dependency.
        /// </summary>
        public readonly string Dependency;
        /// <summary>
        /// The modifier for the dependency.
        /// </summary>
        public readonly string DependencyModifier;
        /// <summary>
        /// The type of the dependency.
        /// </summary>
        public readonly string DependencyType;

        [OutputConstructor]
        private GetSoftwareSourceSoftwarePackageDependencyResult(
            string dependency,

            string dependencyModifier,

            string dependencyType)
        {
            Dependency = dependency;
            DependencyModifier = dependencyModifier;
            DependencyType = dependencyType;
        }
    }
}