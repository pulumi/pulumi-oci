// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionMetricListArgs;
import com.pulumi.oci.StackMonitoring.inputs.MetricExtensionQueryPropertiesArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MetricExtensionArgs extends com.pulumi.resources.ResourceArgs {

    public static final MetricExtensionArgs Empty = new MetricExtensionArgs();

    /**
     * (Updatable) Schedule of metric extension should use RFC 5545 format i.e. recur-rule-part = &#34;FREQ&#34;;INTERVAL where FREQ rule part identifies the type of recurrence rule. Valid values are &#34;MINUTELY&#34;,&#34;HOURLY&#34;,&#34;DAILY&#34; to specify repeating events based on an interval of a minute, an hour and a day or more. Example- FREQ=DAILY;INTERVAL=1
     * 
     */
    @Import(name="collectionRecurrences", required=true)
    private Output<String> collectionRecurrences;

    /**
     * @return (Updatable) Schedule of metric extension should use RFC 5545 format i.e. recur-rule-part = &#34;FREQ&#34;;INTERVAL where FREQ rule part identifies the type of recurrence rule. Valid values are &#34;MINUTELY&#34;,&#34;HOURLY&#34;,&#34;DAILY&#34; to specify repeating events based on an interval of a minute, an hour and a day or more. Example- FREQ=DAILY;INTERVAL=1
     * 
     */
    public Output<String> collectionRecurrences() {
        return this.collectionRecurrences;
    }

    /**
     * (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Description of the metric extension.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Description of the metric extension.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Metric Extension display name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Metric Extension display name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) List of metrics which are part of this metric extension
     * 
     */
    @Import(name="metricLists", required=true)
    private Output<List<MetricExtensionMetricListArgs>> metricLists;

    /**
     * @return (Updatable) List of metrics which are part of this metric extension
     * 
     */
    public Output<List<MetricExtensionMetricListArgs>> metricLists() {
        return this.metricLists;
    }

    /**
     * Metric Extension Resource name.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Metric Extension Resource name.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) An optional property when set to `true` triggers Publish of a metric extension. Once set to `true`, it cannot be changed back to `false`. Update of publish_trigger cannot be combined with other updates in the same request. A metric extension cannot be tested and its definition cannot be updated once it is marked published or publish_trigger is updated to `true`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="publishTrigger")
    private @Nullable Output<Boolean> publishTrigger;

    /**
     * @return (Updatable) An optional property when set to `true` triggers Publish of a metric extension. Once set to `true`, it cannot be changed back to `false`. Update of publish_trigger cannot be combined with other updates in the same request. A metric extension cannot be tested and its definition cannot be updated once it is marked published or publish_trigger is updated to `true`.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Boolean>> publishTrigger() {
        return Optional.ofNullable(this.publishTrigger);
    }

    /**
     * (Updatable) Collection method and query properties details of metric extension
     * 
     */
    @Import(name="queryProperties", required=true)
    private Output<MetricExtensionQueryPropertiesArgs> queryProperties;

    /**
     * @return (Updatable) Collection method and query properties details of metric extension
     * 
     */
    public Output<MetricExtensionQueryPropertiesArgs> queryProperties() {
        return this.queryProperties;
    }

    /**
     * Resource type to which Metric Extension applies
     * 
     */
    @Import(name="resourceType", required=true)
    private Output<String> resourceType;

    /**
     * @return Resource type to which Metric Extension applies
     * 
     */
    public Output<String> resourceType() {
        return this.resourceType;
    }

    private MetricExtensionArgs() {}

    private MetricExtensionArgs(MetricExtensionArgs $) {
        this.collectionRecurrences = $.collectionRecurrences;
        this.compartmentId = $.compartmentId;
        this.description = $.description;
        this.displayName = $.displayName;
        this.metricLists = $.metricLists;
        this.name = $.name;
        this.publishTrigger = $.publishTrigger;
        this.queryProperties = $.queryProperties;
        this.resourceType = $.resourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MetricExtensionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MetricExtensionArgs $;

        public Builder() {
            $ = new MetricExtensionArgs();
        }

        public Builder(MetricExtensionArgs defaults) {
            $ = new MetricExtensionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param collectionRecurrences (Updatable) Schedule of metric extension should use RFC 5545 format i.e. recur-rule-part = &#34;FREQ&#34;;INTERVAL where FREQ rule part identifies the type of recurrence rule. Valid values are &#34;MINUTELY&#34;,&#34;HOURLY&#34;,&#34;DAILY&#34; to specify repeating events based on an interval of a minute, an hour and a day or more. Example- FREQ=DAILY;INTERVAL=1
         * 
         * @return builder
         * 
         */
        public Builder collectionRecurrences(Output<String> collectionRecurrences) {
            $.collectionRecurrences = collectionRecurrences;
            return this;
        }

        /**
         * @param collectionRecurrences (Updatable) Schedule of metric extension should use RFC 5545 format i.e. recur-rule-part = &#34;FREQ&#34;;INTERVAL where FREQ rule part identifies the type of recurrence rule. Valid values are &#34;MINUTELY&#34;,&#34;HOURLY&#34;,&#34;DAILY&#34; to specify repeating events based on an interval of a minute, an hour and a day or more. Example- FREQ=DAILY;INTERVAL=1
         * 
         * @return builder
         * 
         */
        public Builder collectionRecurrences(String collectionRecurrences) {
            return collectionRecurrences(Output.of(collectionRecurrences));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param description (Updatable) Description of the metric extension.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Description of the metric extension.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Metric Extension display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Metric Extension display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param metricLists (Updatable) List of metrics which are part of this metric extension
         * 
         * @return builder
         * 
         */
        public Builder metricLists(Output<List<MetricExtensionMetricListArgs>> metricLists) {
            $.metricLists = metricLists;
            return this;
        }

        /**
         * @param metricLists (Updatable) List of metrics which are part of this metric extension
         * 
         * @return builder
         * 
         */
        public Builder metricLists(List<MetricExtensionMetricListArgs> metricLists) {
            return metricLists(Output.of(metricLists));
        }

        /**
         * @param metricLists (Updatable) List of metrics which are part of this metric extension
         * 
         * @return builder
         * 
         */
        public Builder metricLists(MetricExtensionMetricListArgs... metricLists) {
            return metricLists(List.of(metricLists));
        }

        /**
         * @param name Metric Extension Resource name.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Metric Extension Resource name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param publishTrigger (Updatable) An optional property when set to `true` triggers Publish of a metric extension. Once set to `true`, it cannot be changed back to `false`. Update of publish_trigger cannot be combined with other updates in the same request. A metric extension cannot be tested and its definition cannot be updated once it is marked published or publish_trigger is updated to `true`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder publishTrigger(@Nullable Output<Boolean> publishTrigger) {
            $.publishTrigger = publishTrigger;
            return this;
        }

        /**
         * @param publishTrigger (Updatable) An optional property when set to `true` triggers Publish of a metric extension. Once set to `true`, it cannot be changed back to `false`. Update of publish_trigger cannot be combined with other updates in the same request. A metric extension cannot be tested and its definition cannot be updated once it is marked published or publish_trigger is updated to `true`.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder publishTrigger(Boolean publishTrigger) {
            return publishTrigger(Output.of(publishTrigger));
        }

        /**
         * @param queryProperties (Updatable) Collection method and query properties details of metric extension
         * 
         * @return builder
         * 
         */
        public Builder queryProperties(Output<MetricExtensionQueryPropertiesArgs> queryProperties) {
            $.queryProperties = queryProperties;
            return this;
        }

        /**
         * @param queryProperties (Updatable) Collection method and query properties details of metric extension
         * 
         * @return builder
         * 
         */
        public Builder queryProperties(MetricExtensionQueryPropertiesArgs queryProperties) {
            return queryProperties(Output.of(queryProperties));
        }

        /**
         * @param resourceType Resource type to which Metric Extension applies
         * 
         * @return builder
         * 
         */
        public Builder resourceType(Output<String> resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param resourceType Resource type to which Metric Extension applies
         * 
         * @return builder
         * 
         */
        public Builder resourceType(String resourceType) {
            return resourceType(Output.of(resourceType));
        }

        public MetricExtensionArgs build() {
            if ($.collectionRecurrences == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "collectionRecurrences");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "compartmentId");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "displayName");
            }
            if ($.metricLists == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "metricLists");
            }
            if ($.queryProperties == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "queryProperties");
            }
            if ($.resourceType == null) {
                throw new MissingRequiredPropertyException("MetricExtensionArgs", "resourceType");
            }
            return $;
        }
    }

}
