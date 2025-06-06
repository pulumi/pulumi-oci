// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class GetScriptsScriptCollectionItemResult
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        public readonly string ApmDomainId;
        /// <summary>
        /// The content of the script. It may contain custom-defined tags that can be used for setting dynamic parameters. The format to set dynamic parameters is: `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;OS&gt;isParamValueSecret(true/false)&lt;/OS&gt;&lt;/ORAP&gt;`. Param value and isParamValueSecret are optional, the default value for isParamValueSecret is false. Examples: With mandatory param name : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;/ORAP&gt;` With parameter name and value : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;/ORAP&gt;` Note that the content is valid if it matches the given content type. For example, if the content type is SIDE, then the content should be in Side script format. If the content type is JS, then the content should be in JavaScript format. If the content type is PLAYWRIGHT_TS, then the content should be in TypeScript format.
        /// </summary>
        public readonly string Content;
        /// <summary>
        /// File name of the uploaded script content.
        /// </summary>
        public readonly string ContentFileName;
        /// <summary>
        /// Size of the script content.
        /// </summary>
        public readonly int ContentSizeInBytes;
        /// <summary>
        /// A filter to return only resources that match the content type given.
        /// </summary>
        public readonly string ContentType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only the resources that match the entire display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details of the monitor count per state. Example: `{ "total" : 5, "enabled" : 3 , "disabled" : 2, "invalid" : 0 }`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetScriptsScriptCollectionItemMonitorStatusCountMapResult> MonitorStatusCountMaps;
        /// <summary>
        /// List of script parameters. Example: `[{"scriptParameter": {"paramName": "userid", "paramValue":"testuser", "isSecret": false}, "isOverwritten": false}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetScriptsScriptCollectionItemParameterResult> Parameters;
        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The time the script was uploaded.
        /// </summary>
        public readonly string TimeUploaded;

        [OutputConstructor]
        private GetScriptsScriptCollectionItemResult(
            string apmDomainId,

            string content,

            string contentFileName,

            int contentSizeInBytes,

            string contentType,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetScriptsScriptCollectionItemMonitorStatusCountMapResult> monitorStatusCountMaps,

            ImmutableArray<Outputs.GetScriptsScriptCollectionItemParameterResult> parameters,

            string timeCreated,

            string timeUpdated,

            string timeUploaded)
        {
            ApmDomainId = apmDomainId;
            Content = content;
            ContentFileName = contentFileName;
            ContentSizeInBytes = contentSizeInBytes;
            ContentType = contentType;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            MonitorStatusCountMaps = monitorStatusCountMaps;
            Parameters = parameters;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TimeUploaded = timeUploaded;
        }
    }
}
