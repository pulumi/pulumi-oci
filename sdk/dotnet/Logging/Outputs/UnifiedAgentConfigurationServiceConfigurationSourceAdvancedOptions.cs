// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class UnifiedAgentConfigurationServiceConfigurationSourceAdvancedOptions
    {
        /// <summary>
        /// (Updatable) Starts to read the logs from the head of the file or the last read position recorded in pos_file, not tail.
        /// </summary>
        public readonly bool? IsReadFromHead;

        [OutputConstructor]
        private UnifiedAgentConfigurationServiceConfigurationSourceAdvancedOptions(bool? isReadFromHead)
        {
            IsReadFromHead = isReadFromHead;
        }
    }
}
