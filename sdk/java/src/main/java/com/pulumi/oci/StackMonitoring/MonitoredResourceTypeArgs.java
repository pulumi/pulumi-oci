// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceTypeMetadataArgs;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceTypeArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceTypeArgs Empty = new MonitoredResourceTypeArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
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
     * (Updatable) A friendly description.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A friendly description.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Monitored resource type display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Monitored resource type display name.
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
     * (Updatable) The metadata details for resource type.
     * 
     */
    @Import(name="metadata")
    private @Nullable Output<MonitoredResourceTypeMetadataArgs> metadata;

    /**
     * @return (Updatable) The metadata details for resource type.
     * 
     */
    public Optional<Output<MonitoredResourceTypeMetadataArgs>> metadata() {
        return Optional.ofNullable(this.metadata);
    }

    /**
     * (Updatable) Metric namespace for resource type.
     * 
     */
    @Import(name="metricNamespace")
    private @Nullable Output<String> metricNamespace;

    /**
     * @return (Updatable) Metric namespace for resource type.
     * 
     */
    public Optional<Output<String>> metricNamespace() {
        return Optional.ofNullable(this.metricNamespace);
    }

    /**
     * A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private MonitoredResourceTypeArgs() {}

    private MonitoredResourceTypeArgs(MonitoredResourceTypeArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.metadata = $.metadata;
        this.metricNamespace = $.metricNamespace;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceTypeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceTypeArgs $;

        public Builder() {
            $ = new MonitoredResourceTypeArgs();
        }

        public Builder(MonitoredResourceTypeArgs defaults) {
            $ = new MonitoredResourceTypeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy containing the resource type.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
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
         * @param description (Updatable) A friendly description.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A friendly description.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Monitored resource type display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Monitored resource type display name.
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
         * @param metadata (Updatable) The metadata details for resource type.
         * 
         * @return builder
         * 
         */
        public Builder metadata(@Nullable Output<MonitoredResourceTypeMetadataArgs> metadata) {
            $.metadata = metadata;
            return this;
        }

        /**
         * @param metadata (Updatable) The metadata details for resource type.
         * 
         * @return builder
         * 
         */
        public Builder metadata(MonitoredResourceTypeMetadataArgs metadata) {
            return metadata(Output.of(metadata));
        }

        /**
         * @param metricNamespace (Updatable) Metric namespace for resource type.
         * 
         * @return builder
         * 
         */
        public Builder metricNamespace(@Nullable Output<String> metricNamespace) {
            $.metricNamespace = metricNamespace;
            return this;
        }

        /**
         * @param metricNamespace (Updatable) Metric namespace for resource type.
         * 
         * @return builder
         * 
         */
        public Builder metricNamespace(String metricNamespace) {
            return metricNamespace(Output.of(metricNamespace));
        }

        /**
         * @param name A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A unique monitored resource type name. The name must be unique across tenancy.  Name can not be changed.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public MonitoredResourceTypeArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}