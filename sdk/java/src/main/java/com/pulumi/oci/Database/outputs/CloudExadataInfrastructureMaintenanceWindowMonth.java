// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class CloudExadataInfrastructureMaintenanceWindowMonth {
    /**
     * @return (Updatable) Name of the month of the year.
     * 
     */
    private String name;

    private CloudExadataInfrastructureMaintenanceWindowMonth() {}
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

    public static Builder builder(CloudExadataInfrastructureMaintenanceWindowMonth defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(CloudExadataInfrastructureMaintenanceWindowMonth defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("CloudExadataInfrastructureMaintenanceWindowMonth", "name");
            }
            this.name = name;
            return this;
        }
        public CloudExadataInfrastructureMaintenanceWindowMonth build() {
            final var _resultValue = new CloudExadataInfrastructureMaintenanceWindowMonth();
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
