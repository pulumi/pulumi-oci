// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstanceMaintenanceRebootResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String instanceId;
    /**
     * @return The maximum extension date and time for the maintenance reboot, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). The range for the maintenance extension is between 1 and 14 days from the initial scheduled maintenance date. Example: `2018-05-25T21:10:29.600Z`
     * 
     */
    private String timeMaintenanceRebootDueMax;

    private GetInstanceMaintenanceRebootResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String instanceId() {
        return this.instanceId;
    }
    /**
     * @return The maximum extension date and time for the maintenance reboot, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). The range for the maintenance extension is between 1 and 14 days from the initial scheduled maintenance date. Example: `2018-05-25T21:10:29.600Z`
     * 
     */
    public String timeMaintenanceRebootDueMax() {
        return this.timeMaintenanceRebootDueMax;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceMaintenanceRebootResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String instanceId;
        private String timeMaintenanceRebootDueMax;
        public Builder() {}
        public Builder(GetInstanceMaintenanceRebootResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.instanceId = defaults.instanceId;
    	      this.timeMaintenanceRebootDueMax = defaults.timeMaintenanceRebootDueMax;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceRebootResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder instanceId(String instanceId) {
            if (instanceId == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceRebootResult", "instanceId");
            }
            this.instanceId = instanceId;
            return this;
        }
        @CustomType.Setter
        public Builder timeMaintenanceRebootDueMax(String timeMaintenanceRebootDueMax) {
            if (timeMaintenanceRebootDueMax == null) {
              throw new MissingRequiredPropertyException("GetInstanceMaintenanceRebootResult", "timeMaintenanceRebootDueMax");
            }
            this.timeMaintenanceRebootDueMax = timeMaintenanceRebootDueMax;
            return this;
        }
        public GetInstanceMaintenanceRebootResult build() {
            final var _resultValue = new GetInstanceMaintenanceRebootResult();
            _resultValue.id = id;
            _resultValue.instanceId = instanceId;
            _resultValue.timeMaintenanceRebootDueMax = timeMaintenanceRebootDueMax;
            return _resultValue;
        }
    }
}
