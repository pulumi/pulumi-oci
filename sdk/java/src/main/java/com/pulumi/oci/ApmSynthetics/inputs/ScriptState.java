// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmSynthetics.inputs.ScriptMonitorStatusCountMapArgs;
import com.pulumi.oci.ApmSynthetics.inputs.ScriptParameterArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ScriptState extends com.pulumi.resources.ResourceArgs {

    public static final ScriptState Empty = new ScriptState();

    /**
     * (Updatable) The APM domain ID the request is intended for.
     * 
     */
    @Import(name="apmDomainId")
    private @Nullable Output<String> apmDomainId;

    /**
     * @return (Updatable) The APM domain ID the request is intended for.
     * 
     */
    public Optional<Output<String>> apmDomainId() {
        return Optional.ofNullable(this.apmDomainId);
    }

    /**
     * (Updatable) The content of the script. It may contain custom-defined tags that can be used for setting dynamic parameters. The format to set dynamic parameters is: `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;OS&gt;isParamValueSecret(true/false)&lt;/OS&gt;&lt;/ORAP&gt;`. Param value and isParamValueSecret are optional, the default value for isParamValueSecret is false. Examples: With mandatory param name : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;/ORAP&gt;` With parameter name and value : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;/ORAP&gt;` Note that the content is valid if it matches the given content type. For example, if the content type is SIDE, then the content should be in Side script format. If the content type is JS, then the content should be in JavaScript format.
     * 
     */
    @Import(name="content")
    private @Nullable Output<String> content;

    /**
     * @return (Updatable) The content of the script. It may contain custom-defined tags that can be used for setting dynamic parameters. The format to set dynamic parameters is: `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;OS&gt;isParamValueSecret(true/false)&lt;/OS&gt;&lt;/ORAP&gt;`. Param value and isParamValueSecret are optional, the default value for isParamValueSecret is false. Examples: With mandatory param name : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;/ORAP&gt;` With parameter name and value : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;/ORAP&gt;` Note that the content is valid if it matches the given content type. For example, if the content type is SIDE, then the content should be in Side script format. If the content type is JS, then the content should be in JavaScript format.
     * 
     */
    public Optional<Output<String>> content() {
        return Optional.ofNullable(this.content);
    }

    /**
     * (Updatable) File name of uploaded script content.
     * 
     */
    @Import(name="contentFileName")
    private @Nullable Output<String> contentFileName;

    /**
     * @return (Updatable) File name of uploaded script content.
     * 
     */
    public Optional<Output<String>> contentFileName() {
        return Optional.ofNullable(this.contentFileName);
    }

    /**
     * Size of the script content.
     * 
     */
    @Import(name="contentSizeInBytes")
    private @Nullable Output<Integer> contentSizeInBytes;

    /**
     * @return Size of the script content.
     * 
     */
    public Optional<Output<Integer>> contentSizeInBytes() {
        return Optional.ofNullable(this.contentSizeInBytes);
    }

    /**
     * (Updatable) Content type of script.
     * 
     */
    @Import(name="contentType")
    private @Nullable Output<String> contentType;

    /**
     * @return (Updatable) Content type of script.
     * 
     */
    public Optional<Output<String>> contentType() {
        return Optional.ofNullable(this.contentType);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Unique name that can be edited. The name should not contain any confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    @Import(name="monitorStatusCountMaps")
    private @Nullable Output<List<ScriptMonitorStatusCountMapArgs>> monitorStatusCountMaps;

    /**
     * @return Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
     * 
     */
    public Optional<Output<List<ScriptMonitorStatusCountMapArgs>>> monitorStatusCountMaps() {
        return Optional.ofNullable(this.monitorStatusCountMaps);
    }

    /**
     * (Updatable) List of script parameters. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;, &#34;isSecret&#34;: false}]`
     * 
     */
    @Import(name="parameters")
    private @Nullable Output<List<ScriptParameterArgs>> parameters;

    /**
     * @return (Updatable) List of script parameters. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;, &#34;isSecret&#34;: false}]`
     * 
     */
    public Optional<Output<List<ScriptParameterArgs>>> parameters() {
        return Optional.ofNullable(this.parameters);
    }

    /**
     * The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * The time the script was uploaded.
     * 
     */
    @Import(name="timeUploaded")
    private @Nullable Output<String> timeUploaded;

    /**
     * @return The time the script was uploaded.
     * 
     */
    public Optional<Output<String>> timeUploaded() {
        return Optional.ofNullable(this.timeUploaded);
    }

    private ScriptState() {}

    private ScriptState(ScriptState $) {
        this.apmDomainId = $.apmDomainId;
        this.content = $.content;
        this.contentFileName = $.contentFileName;
        this.contentSizeInBytes = $.contentSizeInBytes;
        this.contentType = $.contentType;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.monitorStatusCountMaps = $.monitorStatusCountMaps;
        this.parameters = $.parameters;
        this.timeCreated = $.timeCreated;
        this.timeUpdated = $.timeUpdated;
        this.timeUploaded = $.timeUploaded;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ScriptState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ScriptState $;

        public Builder() {
            $ = new ScriptState();
        }

        public Builder(ScriptState defaults) {
            $ = new ScriptState(Objects.requireNonNull(defaults));
        }

        /**
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(@Nullable Output<String> apmDomainId) {
            $.apmDomainId = apmDomainId;
            return this;
        }

        /**
         * @param apmDomainId (Updatable) The APM domain ID the request is intended for.
         * 
         * @return builder
         * 
         */
        public Builder apmDomainId(String apmDomainId) {
            return apmDomainId(Output.of(apmDomainId));
        }

        /**
         * @param content (Updatable) The content of the script. It may contain custom-defined tags that can be used for setting dynamic parameters. The format to set dynamic parameters is: `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;OS&gt;isParamValueSecret(true/false)&lt;/OS&gt;&lt;/ORAP&gt;`. Param value and isParamValueSecret are optional, the default value for isParamValueSecret is false. Examples: With mandatory param name : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;/ORAP&gt;` With parameter name and value : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;/ORAP&gt;` Note that the content is valid if it matches the given content type. For example, if the content type is SIDE, then the content should be in Side script format. If the content type is JS, then the content should be in JavaScript format.
         * 
         * @return builder
         * 
         */
        public Builder content(@Nullable Output<String> content) {
            $.content = content;
            return this;
        }

        /**
         * @param content (Updatable) The content of the script. It may contain custom-defined tags that can be used for setting dynamic parameters. The format to set dynamic parameters is: `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;OS&gt;isParamValueSecret(true/false)&lt;/OS&gt;&lt;/ORAP&gt;`. Param value and isParamValueSecret are optional, the default value for isParamValueSecret is false. Examples: With mandatory param name : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;/ORAP&gt;` With parameter name and value : `&lt;ORAP&gt;&lt;ON&gt;param name&lt;/ON&gt;&lt;OV&gt;param value&lt;/OV&gt;&lt;/ORAP&gt;` Note that the content is valid if it matches the given content type. For example, if the content type is SIDE, then the content should be in Side script format. If the content type is JS, then the content should be in JavaScript format.
         * 
         * @return builder
         * 
         */
        public Builder content(String content) {
            return content(Output.of(content));
        }

        /**
         * @param contentFileName (Updatable) File name of uploaded script content.
         * 
         * @return builder
         * 
         */
        public Builder contentFileName(@Nullable Output<String> contentFileName) {
            $.contentFileName = contentFileName;
            return this;
        }

        /**
         * @param contentFileName (Updatable) File name of uploaded script content.
         * 
         * @return builder
         * 
         */
        public Builder contentFileName(String contentFileName) {
            return contentFileName(Output.of(contentFileName));
        }

        /**
         * @param contentSizeInBytes Size of the script content.
         * 
         * @return builder
         * 
         */
        public Builder contentSizeInBytes(@Nullable Output<Integer> contentSizeInBytes) {
            $.contentSizeInBytes = contentSizeInBytes;
            return this;
        }

        /**
         * @param contentSizeInBytes Size of the script content.
         * 
         * @return builder
         * 
         */
        public Builder contentSizeInBytes(Integer contentSizeInBytes) {
            return contentSizeInBytes(Output.of(contentSizeInBytes));
        }

        /**
         * @param contentType (Updatable) Content type of script.
         * 
         * @return builder
         * 
         */
        public Builder contentType(@Nullable Output<String> contentType) {
            $.contentType = contentType;
            return this;
        }

        /**
         * @param contentType (Updatable) Content type of script.
         * 
         * @return builder
         * 
         */
        public Builder contentType(String contentType) {
            return contentType(Output.of(contentType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Unique name that can be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Unique name that can be edited. The name should not contain any confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(@Nullable Output<List<ScriptMonitorStatusCountMapArgs>> monitorStatusCountMaps) {
            $.monitorStatusCountMaps = monitorStatusCountMaps;
            return this;
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(List<ScriptMonitorStatusCountMapArgs> monitorStatusCountMaps) {
            return monitorStatusCountMaps(Output.of(monitorStatusCountMaps));
        }

        /**
         * @param monitorStatusCountMaps Details of the monitor count per state. Example: `{ &#34;total&#34; : 5, &#34;enabled&#34; : 3 , &#34;disabled&#34; : 2, &#34;invalid&#34; : 0 }`
         * 
         * @return builder
         * 
         */
        public Builder monitorStatusCountMaps(ScriptMonitorStatusCountMapArgs... monitorStatusCountMaps) {
            return monitorStatusCountMaps(List.of(monitorStatusCountMaps));
        }

        /**
         * @param parameters (Updatable) List of script parameters. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;, &#34;isSecret&#34;: false}]`
         * 
         * @return builder
         * 
         */
        public Builder parameters(@Nullable Output<List<ScriptParameterArgs>> parameters) {
            $.parameters = parameters;
            return this;
        }

        /**
         * @param parameters (Updatable) List of script parameters. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;, &#34;isSecret&#34;: false}]`
         * 
         * @return builder
         * 
         */
        public Builder parameters(List<ScriptParameterArgs> parameters) {
            return parameters(Output.of(parameters));
        }

        /**
         * @param parameters (Updatable) List of script parameters. Example: `[{&#34;paramName&#34;: &#34;userid&#34;, &#34;paramValue&#34;:&#34;testuser&#34;, &#34;isSecret&#34;: false}]`
         * 
         * @return builder
         * 
         */
        public Builder parameters(ScriptParameterArgs... parameters) {
            return parameters(List.of(parameters));
        }

        /**
         * @param timeCreated The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeUpdated The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param timeUploaded The time the script was uploaded.
         * 
         * @return builder
         * 
         */
        public Builder timeUploaded(@Nullable Output<String> timeUploaded) {
            $.timeUploaded = timeUploaded;
            return this;
        }

        /**
         * @param timeUploaded The time the script was uploaded.
         * 
         * @return builder
         * 
         */
        public Builder timeUploaded(String timeUploaded) {
            return timeUploaded(Output.of(timeUploaded));
        }

        public ScriptState build() {
            return $;
        }
    }

}