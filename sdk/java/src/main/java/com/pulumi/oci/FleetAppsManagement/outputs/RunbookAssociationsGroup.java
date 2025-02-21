// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.RunbookAssociationsGroupProperties;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RunbookAssociationsGroup {
    /**
     * @return (Updatable) The name of the group.
     * 
     */
    private String name;
    /**
     * @return (Updatable) The properties of the component.
     * 
     */
    private @Nullable RunbookAssociationsGroupProperties properties;
    /**
     * @return (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP : Executes tasks across resources in a rolling order.
     * 
     */
    private String type;

    private RunbookAssociationsGroup() {}
    /**
     * @return (Updatable) The name of the group.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) The properties of the component.
     * 
     */
    public Optional<RunbookAssociationsGroupProperties> properties() {
        return Optional.ofNullable(this.properties);
    }
    /**
     * @return (Updatable) The type of the group. PARALLEL_TASK_GROUP : Helps to execute tasks parallelly inside a resource. PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly. ROLLING_RESOURCE_GROUP : Executes tasks across resources in a rolling order.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunbookAssociationsGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private @Nullable RunbookAssociationsGroupProperties properties;
        private String type;
        public Builder() {}
        public Builder(RunbookAssociationsGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.properties = defaults.properties;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("RunbookAssociationsGroup", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder properties(@Nullable RunbookAssociationsGroupProperties properties) {

            this.properties = properties;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("RunbookAssociationsGroup", "type");
            }
            this.type = type;
            return this;
        }
        public RunbookAssociationsGroup build() {
            final var _resultValue = new RunbookAssociationsGroup();
            _resultValue.name = name;
            _resultValue.properties = properties;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
