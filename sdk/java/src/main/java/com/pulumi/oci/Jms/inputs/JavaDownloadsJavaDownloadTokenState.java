// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Jms.inputs.JavaDownloadsJavaDownloadTokenCreatedByArgs;
import com.pulumi.oci.Jms.inputs.JavaDownloadsJavaDownloadTokenLastUpdatedByArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class JavaDownloadsJavaDownloadTokenState extends com.pulumi.resources.ResourceArgs {

    public static final JavaDownloadsJavaDownloadTokenState Empty = new JavaDownloadsJavaDownloadTokenState();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the JavaDownloadToken.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the JavaDownloadToken.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * An authorized principal.
     * 
     */
    @Import(name="createdBies")
    private @Nullable Output<List<JavaDownloadsJavaDownloadTokenCreatedByArgs>> createdBies;

    /**
     * @return An authorized principal.
     * 
     */
    public Optional<Output<List<JavaDownloadsJavaDownloadTokenCreatedByArgs>>> createdBies() {
        return Optional.ofNullable(this.createdBies);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) User provided description of the JavaDownloadToken.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) User provided description of the JavaDownloadToken.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) User provided display name of the JavaDownloadToken.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) User provided display name of the JavaDownloadToken.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) The token default attribute.
     * 
     */
    @Import(name="isDefault")
    private @Nullable Output<Boolean> isDefault;

    /**
     * @return (Updatable) The token default attribute.
     * 
     */
    public Optional<Output<Boolean>> isDefault() {
        return Optional.ofNullable(this.isDefault);
    }

    /**
     * The Java version associated with the token.
     * 
     */
    @Import(name="javaVersion")
    private @Nullable Output<String> javaVersion;

    /**
     * @return The Java version associated with the token.
     * 
     */
    public Optional<Output<String>> javaVersion() {
        return Optional.ofNullable(this.javaVersion);
    }

    /**
     * An authorized principal.
     * 
     */
    @Import(name="lastUpdatedBies")
    private @Nullable Output<List<JavaDownloadsJavaDownloadTokenLastUpdatedByArgs>> lastUpdatedBies;

    /**
     * @return An authorized principal.
     * 
     */
    public Optional<Output<List<JavaDownloadsJavaDownloadTokenLastUpdatedByArgs>>> lastUpdatedBies() {
        return Optional.ofNullable(this.lastUpdatedBies);
    }

    /**
     * (Updatable) The license type(s) associated with the JavaDownloadToken.
     * 
     */
    @Import(name="licenseTypes")
    private @Nullable Output<List<String>> licenseTypes;

    /**
     * @return (Updatable) The license type(s) associated with the JavaDownloadToken.
     * 
     */
    public Optional<Output<List<String>>> licenseTypes() {
        return Optional.ofNullable(this.licenseTypes);
    }

    /**
     * Possible lifecycle substates.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Possible lifecycle substates.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The current state of the JavaDownloadToken.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the JavaDownloadToken.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Import(name="systemTags")
    private @Nullable Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> systemTags() {
        return Optional.ofNullable(this.systemTags);
    }

    /**
     * The time the JavaDownloadToken was created, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The time the JavaDownloadToken was created, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) Expiry time of the token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="timeExpires")
    private @Nullable Output<String> timeExpires;

    /**
     * @return (Updatable) Expiry time of the token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> timeExpires() {
        return Optional.ofNullable(this.timeExpires);
    }

    /**
     * The time the JavaDownloadToken was last used for download, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeLastUsed")
    private @Nullable Output<String> timeLastUsed;

    /**
     * @return The time the JavaDownloadToken was last used for download, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeLastUsed() {
        return Optional.ofNullable(this.timeLastUsed);
    }

    /**
     * The time the JavaDownloadToken was updated, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    @Import(name="timeUpdated")
    private @Nullable Output<String> timeUpdated;

    /**
     * @return The time the JavaDownloadToken was updated, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
     * 
     */
    public Optional<Output<String>> timeUpdated() {
        return Optional.ofNullable(this.timeUpdated);
    }

    /**
     * Uniquely generated value for the JavaDownloadToken.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return Uniquely generated value for the JavaDownloadToken.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private JavaDownloadsJavaDownloadTokenState() {}

    private JavaDownloadsJavaDownloadTokenState(JavaDownloadsJavaDownloadTokenState $) {
        this.compartmentId = $.compartmentId;
        this.createdBies = $.createdBies;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.isDefault = $.isDefault;
        this.javaVersion = $.javaVersion;
        this.lastUpdatedBies = $.lastUpdatedBies;
        this.licenseTypes = $.licenseTypes;
        this.lifecycleDetails = $.lifecycleDetails;
        this.state = $.state;
        this.systemTags = $.systemTags;
        this.timeCreated = $.timeCreated;
        this.timeExpires = $.timeExpires;
        this.timeLastUsed = $.timeLastUsed;
        this.timeUpdated = $.timeUpdated;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(JavaDownloadsJavaDownloadTokenState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private JavaDownloadsJavaDownloadTokenState $;

        public Builder() {
            $ = new JavaDownloadsJavaDownloadTokenState();
        }

        public Builder(JavaDownloadsJavaDownloadTokenState defaults) {
            $ = new JavaDownloadsJavaDownloadTokenState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param createdBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder createdBies(@Nullable Output<List<JavaDownloadsJavaDownloadTokenCreatedByArgs>> createdBies) {
            $.createdBies = createdBies;
            return this;
        }

        /**
         * @param createdBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder createdBies(List<JavaDownloadsJavaDownloadTokenCreatedByArgs> createdBies) {
            return createdBies(Output.of(createdBies));
        }

        /**
         * @param createdBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder createdBies(JavaDownloadsJavaDownloadTokenCreatedByArgs... createdBies) {
            return createdBies(List.of(createdBies));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) User provided description of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) User provided description of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) User provided display name of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) User provided display name of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isDefault (Updatable) The token default attribute.
         * 
         * @return builder
         * 
         */
        public Builder isDefault(@Nullable Output<Boolean> isDefault) {
            $.isDefault = isDefault;
            return this;
        }

        /**
         * @param isDefault (Updatable) The token default attribute.
         * 
         * @return builder
         * 
         */
        public Builder isDefault(Boolean isDefault) {
            return isDefault(Output.of(isDefault));
        }

        /**
         * @param javaVersion The Java version associated with the token.
         * 
         * @return builder
         * 
         */
        public Builder javaVersion(@Nullable Output<String> javaVersion) {
            $.javaVersion = javaVersion;
            return this;
        }

        /**
         * @param javaVersion The Java version associated with the token.
         * 
         * @return builder
         * 
         */
        public Builder javaVersion(String javaVersion) {
            return javaVersion(Output.of(javaVersion));
        }

        /**
         * @param lastUpdatedBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder lastUpdatedBies(@Nullable Output<List<JavaDownloadsJavaDownloadTokenLastUpdatedByArgs>> lastUpdatedBies) {
            $.lastUpdatedBies = lastUpdatedBies;
            return this;
        }

        /**
         * @param lastUpdatedBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder lastUpdatedBies(List<JavaDownloadsJavaDownloadTokenLastUpdatedByArgs> lastUpdatedBies) {
            return lastUpdatedBies(Output.of(lastUpdatedBies));
        }

        /**
         * @param lastUpdatedBies An authorized principal.
         * 
         * @return builder
         * 
         */
        public Builder lastUpdatedBies(JavaDownloadsJavaDownloadTokenLastUpdatedByArgs... lastUpdatedBies) {
            return lastUpdatedBies(List.of(lastUpdatedBies));
        }

        /**
         * @param licenseTypes (Updatable) The license type(s) associated with the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder licenseTypes(@Nullable Output<List<String>> licenseTypes) {
            $.licenseTypes = licenseTypes;
            return this;
        }

        /**
         * @param licenseTypes (Updatable) The license type(s) associated with the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder licenseTypes(List<String> licenseTypes) {
            return licenseTypes(Output.of(licenseTypes));
        }

        /**
         * @param licenseTypes (Updatable) The license type(s) associated with the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder licenseTypes(String... licenseTypes) {
            return licenseTypes(List.of(licenseTypes));
        }

        /**
         * @param lifecycleDetails Possible lifecycle substates.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Possible lifecycle substates.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param state The current state of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(@Nullable Output<Map<String,String>> systemTags) {
            $.systemTags = systemTags;
            return this;
        }

        /**
         * @param systemTags System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder systemTags(Map<String,String> systemTags) {
            return systemTags(Output.of(systemTags));
        }

        /**
         * @param timeCreated The time the JavaDownloadToken was created, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The time the JavaDownloadToken was created, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeExpires (Updatable) Expiry time of the token.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(@Nullable Output<String> timeExpires) {
            $.timeExpires = timeExpires;
            return this;
        }

        /**
         * @param timeExpires (Updatable) Expiry time of the token.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeExpires(String timeExpires) {
            return timeExpires(Output.of(timeExpires));
        }

        /**
         * @param timeLastUsed The time the JavaDownloadToken was last used for download, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeLastUsed(@Nullable Output<String> timeLastUsed) {
            $.timeLastUsed = timeLastUsed;
            return this;
        }

        /**
         * @param timeLastUsed The time the JavaDownloadToken was last used for download, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeLastUsed(String timeLastUsed) {
            return timeLastUsed(Output.of(timeLastUsed));
        }

        /**
         * @param timeUpdated The time the JavaDownloadToken was updated, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(@Nullable Output<String> timeUpdated) {
            $.timeUpdated = timeUpdated;
            return this;
        }

        /**
         * @param timeUpdated The time the JavaDownloadToken was updated, displayed as an [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted datetime string.
         * 
         * @return builder
         * 
         */
        public Builder timeUpdated(String timeUpdated) {
            return timeUpdated(Output.of(timeUpdated));
        }

        /**
         * @param value Uniquely generated value for the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value Uniquely generated value for the JavaDownloadToken.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public JavaDownloadsJavaDownloadTokenState build() {
            return $;
        }
    }

}
