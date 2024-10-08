// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BaselineableMetricArgs extends com.pulumi.resources.ResourceArgs {

    public static final BaselineableMetricArgs Empty = new BaselineableMetricArgs();

    /**
     * (Updatable) metric column name
     * 
     */
    @Import(name="column", required=true)
    private Output<String> column;

    /**
     * @return (Updatable) metric column name
     * 
     */
    public Output<String> column() {
        return this.column;
    }

    /**
     * (Updatable) OCID of the compartment
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) OCID of the compartment
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) name of the metric
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) name of the metric
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) namespace of the metric
     * 
     */
    @Import(name="namespace", required=true)
    private Output<String> namespace;

    /**
     * @return (Updatable) namespace of the metric
     * 
     */
    public Output<String> namespace() {
        return this.namespace;
    }

    /**
     * (Updatable) Resource group of the metric
     * 
     */
    @Import(name="resourceGroup")
    private @Nullable Output<String> resourceGroup;

    /**
     * @return (Updatable) Resource group of the metric
     * 
     */
    public Optional<Output<String>> resourceGroup() {
        return Optional.ofNullable(this.resourceGroup);
    }

    /**
     * (Updatable) Resource type of the metric
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="resourceType")
    private @Nullable Output<String> resourceType;

    /**
     * @return (Updatable) Resource type of the metric
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    private BaselineableMetricArgs() {}

    private BaselineableMetricArgs(BaselineableMetricArgs $) {
        this.column = $.column;
        this.compartmentId = $.compartmentId;
        this.name = $.name;
        this.namespace = $.namespace;
        this.resourceGroup = $.resourceGroup;
        this.resourceType = $.resourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BaselineableMetricArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BaselineableMetricArgs $;

        public Builder() {
            $ = new BaselineableMetricArgs();
        }

        public Builder(BaselineableMetricArgs defaults) {
            $ = new BaselineableMetricArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param column (Updatable) metric column name
         * 
         * @return builder
         * 
         */
        public Builder column(Output<String> column) {
            $.column = column;
            return this;
        }

        /**
         * @param column (Updatable) metric column name
         * 
         * @return builder
         * 
         */
        public Builder column(String column) {
            return column(Output.of(column));
        }

        /**
         * @param compartmentId (Updatable) OCID of the compartment
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) OCID of the compartment
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param name (Updatable) name of the metric
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) name of the metric
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param namespace (Updatable) namespace of the metric
         * 
         * @return builder
         * 
         */
        public Builder namespace(Output<String> namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param namespace (Updatable) namespace of the metric
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            return namespace(Output.of(namespace));
        }

        /**
         * @param resourceGroup (Updatable) Resource group of the metric
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(@Nullable Output<String> resourceGroup) {
            $.resourceGroup = resourceGroup;
            return this;
        }

        /**
         * @param resourceGroup (Updatable) Resource group of the metric
         * 
         * @return builder
         * 
         */
        public Builder resourceGroup(String resourceGroup) {
            return resourceGroup(Output.of(resourceGroup));
        }

        /**
         * @param resourceType (Updatable) Resource type of the metric
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable Output<String> resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param resourceType (Updatable) Resource type of the metric
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder resourceType(String resourceType) {
            return resourceType(Output.of(resourceType));
        }

        public BaselineableMetricArgs build() {
            if ($.column == null) {
                throw new MissingRequiredPropertyException("BaselineableMetricArgs", "column");
            }
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("BaselineableMetricArgs", "compartmentId");
            }
            if ($.namespace == null) {
                throw new MissingRequiredPropertyException("BaselineableMetricArgs", "namespace");
            }
            return $;
        }
    }

}
