// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.RunbookVersionGroupPropertiesArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RunbookVersionGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final RunbookVersionGroupArgs Empty = new RunbookVersionGroupArgs();

    /**
     * (Updatable) The name of the group.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The name of the group.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The properties of the component.
     * 
     */
    @Import(name="properties")
    private @Nullable Output<RunbookVersionGroupPropertiesArgs> properties;

    /**
     * @return (Updatable) The properties of the component.
     * 
     */
    public Optional<Output<RunbookVersionGroupPropertiesArgs>> properties() {
        return Optional.ofNullable(this.properties);
    }

    /**
     * (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly
     * inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP :
     * Executes tasks across resources in a rolling order.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly
     * inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP :
     * Executes tasks across resources in a rolling order.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private RunbookVersionGroupArgs() {}

    private RunbookVersionGroupArgs(RunbookVersionGroupArgs $) {
        this.name = $.name;
        this.properties = $.properties;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RunbookVersionGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RunbookVersionGroupArgs $;

        public Builder() {
            $ = new RunbookVersionGroupArgs();
        }

        public Builder(RunbookVersionGroupArgs defaults) {
            $ = new RunbookVersionGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) The name of the group.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The name of the group.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param properties (Updatable) The properties of the component.
         * 
         * @return builder
         * 
         */
        public Builder properties(@Nullable Output<RunbookVersionGroupPropertiesArgs> properties) {
            $.properties = properties;
            return this;
        }

        /**
         * @param properties (Updatable) The properties of the component.
         * 
         * @return builder
         * 
         */
        public Builder properties(RunbookVersionGroupPropertiesArgs properties) {
            return properties(Output.of(properties));
        }

        /**
         * @param type (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly
         * inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP :
         * Executes tasks across resources in a rolling order.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly
         * inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP :
         * Executes tasks across resources in a rolling order.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public RunbookVersionGroupArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("RunbookVersionGroupArgs", "name");
            }
            if ($.type == null) {
                throw new MissingRequiredPropertyException("RunbookVersionGroupArgs", "type");
            }
            return $;
        }
    }

}
