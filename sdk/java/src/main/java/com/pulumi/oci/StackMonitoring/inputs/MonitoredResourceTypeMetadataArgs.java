// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.StackMonitoring.inputs.MonitoredResourceTypeMetadataUniquePropertySetArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MonitoredResourceTypeMetadataArgs extends com.pulumi.resources.ResourceArgs {

    public static final MonitoredResourceTypeMetadataArgs Empty = new MonitoredResourceTypeMetadataArgs();

    /**
     * (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
     * 
     */
    @Import(name="agentProperties")
    private @Nullable Output<List<String>> agentProperties;

    /**
     * @return (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
     * 
     */
    public Optional<Output<List<String>>> agentProperties() {
        return Optional.ofNullable(this.agentProperties);
    }

    /**
     * (Updatable) ResourceType metadata format to be used. Currently supports only one format. Possible values - SYSTEM_FORMAT.
     * * SYSTEM_FORMAT - The resource type metadata is defined in machine friendly format.
     * 
     */
    @Import(name="format", required=true)
    private Output<String> format;

    /**
     * @return (Updatable) ResourceType metadata format to be used. Currently supports only one format. Possible values - SYSTEM_FORMAT.
     * * SYSTEM_FORMAT - The resource type metadata is defined in machine friendly format.
     * 
     */
    public Output<String> format() {
        return this.format;
    }

    /**
     * (Updatable) List of required properties for resource type.
     * 
     */
    @Import(name="requiredProperties")
    private @Nullable Output<List<String>> requiredProperties;

    /**
     * @return (Updatable) List of required properties for resource type.
     * 
     */
    public Optional<Output<List<String>>> requiredProperties() {
        return Optional.ofNullable(this.requiredProperties);
    }

    /**
     * (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
     * 
     */
    @Import(name="uniquePropertySets")
    private @Nullable Output<List<MonitoredResourceTypeMetadataUniquePropertySetArgs>> uniquePropertySets;

    /**
     * @return (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
     * 
     */
    public Optional<Output<List<MonitoredResourceTypeMetadataUniquePropertySetArgs>>> uniquePropertySets() {
        return Optional.ofNullable(this.uniquePropertySets);
    }

    /**
     * (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
     * 
     */
    @Import(name="validPropertiesForCreates")
    private @Nullable Output<List<String>> validPropertiesForCreates;

    /**
     * @return (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
     * 
     */
    public Optional<Output<List<String>>> validPropertiesForCreates() {
        return Optional.ofNullable(this.validPropertiesForCreates);
    }

    /**
     * (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
     * 
     */
    @Import(name="validPropertiesForUpdates")
    private @Nullable Output<List<String>> validPropertiesForUpdates;

    /**
     * @return (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
     * 
     */
    public Optional<Output<List<String>>> validPropertiesForUpdates() {
        return Optional.ofNullable(this.validPropertiesForUpdates);
    }

    /**
     * (Updatable) List of valid values for the properties. This is useful when resource type wants to restrict only certain values for some properties. For instance for &#39;osType&#39; property,  supported values can be restricted to be either Linux or Windows. Example: `{ &#34;osType&#34;: &#34;Linux,Windows,Solaris&#34;}`
     * 
     */
    @Import(name="validPropertyValues")
    private @Nullable Output<Map<String,Object>> validPropertyValues;

    /**
     * @return (Updatable) List of valid values for the properties. This is useful when resource type wants to restrict only certain values for some properties. For instance for &#39;osType&#39; property,  supported values can be restricted to be either Linux or Windows. Example: `{ &#34;osType&#34;: &#34;Linux,Windows,Solaris&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> validPropertyValues() {
        return Optional.ofNullable(this.validPropertyValues);
    }

    private MonitoredResourceTypeMetadataArgs() {}

    private MonitoredResourceTypeMetadataArgs(MonitoredResourceTypeMetadataArgs $) {
        this.agentProperties = $.agentProperties;
        this.format = $.format;
        this.requiredProperties = $.requiredProperties;
        this.uniquePropertySets = $.uniquePropertySets;
        this.validPropertiesForCreates = $.validPropertiesForCreates;
        this.validPropertiesForUpdates = $.validPropertiesForUpdates;
        this.validPropertyValues = $.validPropertyValues;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MonitoredResourceTypeMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MonitoredResourceTypeMetadataArgs $;

        public Builder() {
            $ = new MonitoredResourceTypeMetadataArgs();
        }

        public Builder(MonitoredResourceTypeMetadataArgs defaults) {
            $ = new MonitoredResourceTypeMetadataArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param agentProperties (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
         * 
         * @return builder
         * 
         */
        public Builder agentProperties(@Nullable Output<List<String>> agentProperties) {
            $.agentProperties = agentProperties;
            return this;
        }

        /**
         * @param agentProperties (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
         * 
         * @return builder
         * 
         */
        public Builder agentProperties(List<String> agentProperties) {
            return agentProperties(Output.of(agentProperties));
        }

        /**
         * @param agentProperties (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
         * 
         * @return builder
         * 
         */
        public Builder agentProperties(String... agentProperties) {
            return agentProperties(List.of(agentProperties));
        }

        /**
         * @param format (Updatable) ResourceType metadata format to be used. Currently supports only one format. Possible values - SYSTEM_FORMAT.
         * * SYSTEM_FORMAT - The resource type metadata is defined in machine friendly format.
         * 
         * @return builder
         * 
         */
        public Builder format(Output<String> format) {
            $.format = format;
            return this;
        }

        /**
         * @param format (Updatable) ResourceType metadata format to be used. Currently supports only one format. Possible values - SYSTEM_FORMAT.
         * * SYSTEM_FORMAT - The resource type metadata is defined in machine friendly format.
         * 
         * @return builder
         * 
         */
        public Builder format(String format) {
            return format(Output.of(format));
        }

        /**
         * @param requiredProperties (Updatable) List of required properties for resource type.
         * 
         * @return builder
         * 
         */
        public Builder requiredProperties(@Nullable Output<List<String>> requiredProperties) {
            $.requiredProperties = requiredProperties;
            return this;
        }

        /**
         * @param requiredProperties (Updatable) List of required properties for resource type.
         * 
         * @return builder
         * 
         */
        public Builder requiredProperties(List<String> requiredProperties) {
            return requiredProperties(Output.of(requiredProperties));
        }

        /**
         * @param requiredProperties (Updatable) List of required properties for resource type.
         * 
         * @return builder
         * 
         */
        public Builder requiredProperties(String... requiredProperties) {
            return requiredProperties(List.of(requiredProperties));
        }

        /**
         * @param uniquePropertySets (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
         * 
         * @return builder
         * 
         */
        public Builder uniquePropertySets(@Nullable Output<List<MonitoredResourceTypeMetadataUniquePropertySetArgs>> uniquePropertySets) {
            $.uniquePropertySets = uniquePropertySets;
            return this;
        }

        /**
         * @param uniquePropertySets (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
         * 
         * @return builder
         * 
         */
        public Builder uniquePropertySets(List<MonitoredResourceTypeMetadataUniquePropertySetArgs> uniquePropertySets) {
            return uniquePropertySets(Output.of(uniquePropertySets));
        }

        /**
         * @param uniquePropertySets (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
         * 
         * @return builder
         * 
         */
        public Builder uniquePropertySets(MonitoredResourceTypeMetadataUniquePropertySetArgs... uniquePropertySets) {
            return uniquePropertySets(List.of(uniquePropertySets));
        }

        /**
         * @param validPropertiesForCreates (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForCreates(@Nullable Output<List<String>> validPropertiesForCreates) {
            $.validPropertiesForCreates = validPropertiesForCreates;
            return this;
        }

        /**
         * @param validPropertiesForCreates (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForCreates(List<String> validPropertiesForCreates) {
            return validPropertiesForCreates(Output.of(validPropertiesForCreates));
        }

        /**
         * @param validPropertiesForCreates (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForCreates(String... validPropertiesForCreates) {
            return validPropertiesForCreates(List.of(validPropertiesForCreates));
        }

        /**
         * @param validPropertiesForUpdates (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForUpdates(@Nullable Output<List<String>> validPropertiesForUpdates) {
            $.validPropertiesForUpdates = validPropertiesForUpdates;
            return this;
        }

        /**
         * @param validPropertiesForUpdates (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForUpdates(List<String> validPropertiesForUpdates) {
            return validPropertiesForUpdates(Output.of(validPropertiesForUpdates));
        }

        /**
         * @param validPropertiesForUpdates (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
         * 
         * @return builder
         * 
         */
        public Builder validPropertiesForUpdates(String... validPropertiesForUpdates) {
            return validPropertiesForUpdates(List.of(validPropertiesForUpdates));
        }

        /**
         * @param validPropertyValues (Updatable) List of valid values for the properties. This is useful when resource type wants to restrict only certain values for some properties. For instance for &#39;osType&#39; property,  supported values can be restricted to be either Linux or Windows. Example: `{ &#34;osType&#34;: &#34;Linux,Windows,Solaris&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder validPropertyValues(@Nullable Output<Map<String,Object>> validPropertyValues) {
            $.validPropertyValues = validPropertyValues;
            return this;
        }

        /**
         * @param validPropertyValues (Updatable) List of valid values for the properties. This is useful when resource type wants to restrict only certain values for some properties. For instance for &#39;osType&#39; property,  supported values can be restricted to be either Linux or Windows. Example: `{ &#34;osType&#34;: &#34;Linux,Windows,Solaris&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder validPropertyValues(Map<String,Object> validPropertyValues) {
            return validPropertyValues(Output.of(validPropertyValues));
        }

        public MonitoredResourceTypeMetadataArgs build() {
            $.format = Objects.requireNonNull($.format, "expected parameter 'format' to be non-null");
            return $;
        }
    }

}