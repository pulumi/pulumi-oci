// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek {
    /**
     * @return (Updatable) Name of the month of the year.
     * 
     */
    private String name;

    private AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek() {}
    /**
     * @return (Updatable) Name of the month of the year.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek build() {
            final var o = new AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeek();
            o.name = name;
            return o;
        }
    }
}