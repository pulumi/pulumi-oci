// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class AutonomousDatabaseScheduledOperationDayOfWeek {
    /**
     * @return (Updatable) Name of the day of the week.
     * 
     */
    private String name;

    private AutonomousDatabaseScheduledOperationDayOfWeek() {}
    /**
     * @return (Updatable) Name of the day of the week.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousDatabaseScheduledOperationDayOfWeek defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(AutonomousDatabaseScheduledOperationDayOfWeek defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public AutonomousDatabaseScheduledOperationDayOfWeek build() {
            final var o = new AutonomousDatabaseScheduledOperationDayOfWeek();
            o.name = name;
            return o;
        }
    }
}