// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.SchedulerDefinitionRunBookInputParameterArgumentContentArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class SchedulerDefinitionRunBookInputParameterArgumentArgs extends com.pulumi.resources.ResourceArgs {

    public static final SchedulerDefinitionRunBookInputParameterArgumentArgs Empty = new SchedulerDefinitionRunBookInputParameterArgumentArgs();

    /**
     * (Updatable) Content Source details.
     * 
     */
    @Import(name="content")
    private @Nullable Output<SchedulerDefinitionRunBookInputParameterArgumentContentArgs> content;

    /**
     * @return (Updatable) Content Source details.
     * 
     */
    public Optional<Output<SchedulerDefinitionRunBookInputParameterArgumentContentArgs>> content() {
        return Optional.ofNullable(this.content);
    }

    /**
     * (Updatable) Task argument kind
     * 
     */
    @Import(name="kind", required=true)
    private Output<String> kind;

    /**
     * @return (Updatable) Task argument kind
     * 
     */
    public Output<String> kind() {
        return this.kind;
    }

    /**
     * (Updatable) Name of the input variable
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) Name of the input variable
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) The task input
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) The task input
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private SchedulerDefinitionRunBookInputParameterArgumentArgs() {}

    private SchedulerDefinitionRunBookInputParameterArgumentArgs(SchedulerDefinitionRunBookInputParameterArgumentArgs $) {
        this.content = $.content;
        this.kind = $.kind;
        this.name = $.name;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(SchedulerDefinitionRunBookInputParameterArgumentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private SchedulerDefinitionRunBookInputParameterArgumentArgs $;

        public Builder() {
            $ = new SchedulerDefinitionRunBookInputParameterArgumentArgs();
        }

        public Builder(SchedulerDefinitionRunBookInputParameterArgumentArgs defaults) {
            $ = new SchedulerDefinitionRunBookInputParameterArgumentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param content (Updatable) Content Source details.
         * 
         * @return builder
         * 
         */
        public Builder content(@Nullable Output<SchedulerDefinitionRunBookInputParameterArgumentContentArgs> content) {
            $.content = content;
            return this;
        }

        /**
         * @param content (Updatable) Content Source details.
         * 
         * @return builder
         * 
         */
        public Builder content(SchedulerDefinitionRunBookInputParameterArgumentContentArgs content) {
            return content(Output.of(content));
        }

        /**
         * @param kind (Updatable) Task argument kind
         * 
         * @return builder
         * 
         */
        public Builder kind(Output<String> kind) {
            $.kind = kind;
            return this;
        }

        /**
         * @param kind (Updatable) Task argument kind
         * 
         * @return builder
         * 
         */
        public Builder kind(String kind) {
            return kind(Output.of(kind));
        }

        /**
         * @param name (Updatable) Name of the input variable
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Name of the input variable
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param value (Updatable) The task input
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The task input
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public SchedulerDefinitionRunBookInputParameterArgumentArgs build() {
            if ($.kind == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentArgs", "kind");
            }
            if ($.name == null) {
                throw new MissingRequiredPropertyException("SchedulerDefinitionRunBookInputParameterArgumentArgs", "name");
            }
            return $;
        }
    }

}
